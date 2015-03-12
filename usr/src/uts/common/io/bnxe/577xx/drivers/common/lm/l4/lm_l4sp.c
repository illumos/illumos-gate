
#include "lm5710.h"
#include "lm.h"
#include "lm_l4sp.h"
#include "command.h"
#include "context.h"
#include "bd_chain.h"
#include "mm.h"
#include "mm_l4if.h"
#include "lm_l4fp.h"
#include "lm_l4sp.h"
#include "everest_l5cm_constants.h"
#include "l4debug.h"

/* Sizes of objects that need to be allocated in physical memory */
#define TOE_SP_PHYS_DATA_SIZE ((sizeof(lm_tcp_slow_path_phys_data_t) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
#define TOE_DB_RX_DATA_SIZE   ((sizeof(struct toe_rx_db_data) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
#define TOE_DB_TX_DATA_SIZE   ((sizeof(struct toe_tx_db_data) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)

#define TCP_XCM_DEFAULT_DEL_ACK_MAX_CNT 2

l4_tcp_con_state_t lm_tcp_calc_state (
    lm_device_t    * pdev,
    lm_tcp_state_t * tcp,
    u8_t             fin_was_sent
    );

/** Description Callback function for spe being completed
 *  internally in vbd driver (not via FW)
 */
void lm_tcp_comp_cb(
    struct _lm_device_t *pdev,
    struct sq_pending_command *pending);


/* GilR 11/13/2006 - TODO - ttl is temporarily overloaded for ethearel capture L4/L2 debugging */
#define TOE_DBG_TTL 200
#define ISCSI_DBG_TTL 222

#define TIMERS_TICKS_PER_SEC        (u32_t)(1000)//(1 / TIMERS_TICK_SIZE_CHIP)
#define TSEMI_CLK1_TICKS_PER_SEC    (u32_t)(1000)//(1 / TSEMI_CLK1_RESUL_CHIP)

u32_t lm_get_num_of_cashed_grq_bds(struct _lm_device_t *pdev)
{
    return USTORM_TOE_GRQ_CACHE_NUM_BDS;
}

// this function is used only to verify that the defines above are correct (on compile time - save the runtime checkings...)
static void _fake_func_verify_defines(void)
{
    ASSERT_STATIC( TIMERS_TICKS_PER_SEC     == (1 / TIMERS_TICK_SIZE_CHIP) ) ;
    ASSERT_STATIC( TSEMI_CLK1_TICKS_PER_SEC == (1 / TSEMI_CLK1_RESUL_CHIP) ) ;
}

static __inline u32_t lm_time_resolution(
    lm_device_t *pdev,
    u32_t src_time,
    u32_t src_ticks_per_sec,
    u32_t trg_ticks_per_sec)
{
    u64_t result;
    u64_t tmp_result;
    u32_t dev_factor;

    DbgBreakIf(!(src_ticks_per_sec && trg_ticks_per_sec));

    if (trg_ticks_per_sec > src_ticks_per_sec){
        dev_factor =  trg_ticks_per_sec / src_ticks_per_sec;
        result = src_time * dev_factor;
    } else {
        tmp_result = src_time * trg_ticks_per_sec;

#if defined(_VBD_)
        result = CEIL_DIV(tmp_result, src_ticks_per_sec);
#else
        /* Here we try a avoid 64-bit division operation */
        if (tmp_result < 0xffffffff) {
            result = (u32_t)tmp_result / src_ticks_per_sec;
        } else {
            /* src_ticks_per_sec and trg_ticks_per_sec parameters come
               from NDIS and so far the values observed were 100 or 1000,
               depending on Windows version. These parameters define
               TCP timers resolution and are unlikely to change significantly
               in the future.
               So, here we assume that if (src_time * trg_ticks_per_sec) product
               is out of 32-bit range it is because src_time value.
            */
            DbgBreakIf(src_time < src_ticks_per_sec);
            result = ((u64_t)(src_time / src_ticks_per_sec)) * trg_ticks_per_sec;
        }
#endif
    }

    if(src_time && !result) {
        result = 1;
    }
    DbgMessage(pdev, VERBOSEl4sp,
                "lm_time_resulition: src_time=%d, src_ticks_per_sec=%d, trg_ticks_per_sec=%d, result=%d\n",
                src_time, src_ticks_per_sec, trg_ticks_per_sec, result);

    DbgBreakIf(result > 0xffffffff);
    return (u32_t)result;
}

lm_status_t lm_tcp_erase_connection(
    IN    struct _lm_device_t   * pdev,
    IN    lm_tcp_state_t        * tcp)
{
    lm_status_t status = LM_STATUS_SUCCESS;
    lm_tcp_con_t *rx_con;
    lm_tcp_con_t *tx_con;
    MM_INIT_TCP_LOCK_HANDLE();
    if (!lm_fl_reset_is_inprogress(pdev)) {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, FATAL, "##lm_tcp_erase_connection(0x%x)\n",tcp->cid);
    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        rx_con = tcp->rx_con;
        tx_con = tcp->tx_con;
        mm_acquire_tcp_lock(pdev, tx_con);
        tx_con->flags |= TCP_POST_BLOCKED;
        lm_tcp_abort_bufs(pdev, tcp, tx_con, LM_STATUS_CONNECTION_CLOSED);
        if (tx_con->abortion_under_flr) {
            DbgMessage(pdev, FATAL, "##lm_tcp_erase_connection(0x%x): Tx aborted\n",tcp->cid);
        }
        mm_release_tcp_lock(pdev, tx_con);

        /* Rx abortive part... */

        mm_acquire_tcp_lock(pdev, rx_con);
        /* Abort pending buffers */
        rx_con->flags |= TCP_POST_BLOCKED;
        if (mm_tcp_indicating_bufs(rx_con)) {
            DbgMessage(pdev, FATAL, "##lm_tcp_erase_connection(0x%x): under indication\n",tcp->cid);
            DbgBreak();
            mm_release_tcp_lock(pdev, rx_con);
            return LM_STATUS_FAILURE;
        }
        lm_tcp_abort_bufs(pdev, tcp, rx_con, LM_STATUS_CONNECTION_CLOSED);
        if (rx_con->abortion_under_flr) {
            DbgMessage(pdev, FATAL, "##lm_tcp_erase_connection(0x%x): Rx aborted\n",tcp->cid);
        }

        mm_release_tcp_lock(pdev, rx_con);
    }
    mm_tcp_del_tcp_state(pdev,tcp);
    return status;
}

void lm_tcp_flush_db(
    struct _lm_device_t * pdev,
    lm_tcp_state_t *tcp)
{
    struct toe_tx_doorbell  dq_flush_msg;
    lm_tcp_con_t *rx_con, *tx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgBreakIf(!(pdev && tcp));

    if (tcp->ulp_type != TOE_CONNECTION_TYPE) {
        DbgMessage(pdev, WARNl4sp, "##lm_tcp_flush_db is not sent for connection(0x%x) of type %d\n",tcp->cid, tcp->ulp_type);
        return;
    }

    DbgMessage(pdev, INFORMl4sp, "##lm_tcp_flush_db (cid=0x%x)\n",tcp->cid);
    rx_con = tcp->rx_con;
    tx_con = tcp->tx_con;

    dq_flush_msg.hdr.data = (TOE_CONNECTION_TYPE << DOORBELL_HDR_T_CONN_TYPE_SHIFT);
    dq_flush_msg.params = TOE_TX_DOORBELL_FLUSH;
    dq_flush_msg.nbytes = 0;


    mm_acquire_tcp_lock(pdev, tx_con);
    tx_con->flags |= TCP_DB_BLOCKED;
    mm_release_tcp_lock(pdev, tx_con);

    mm_acquire_tcp_lock(pdev, rx_con);
    rx_con->flags |= TCP_DB_BLOCKED;
    mm_release_tcp_lock(pdev, rx_con);

    DOORBELL(pdev, tcp->cid, *((u32_t *)&dq_flush_msg));
}

/* Desciption:
 *  allocate l4 resources
 * Assumptions:
 *  - lm_init_params was already called
 * Returns:
 *  SUCCESS or any failure */
static lm_status_t lm_tcp_alloc_resc(lm_device_t *pdev)
{
    lm_toe_info_t *toe_info;
    lm_bd_chain_t *bd_chain;
    u32_t mem_size;
    long i;
    u8_t mm_cli_idx       = 0;

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_alloc_resc\n");

    // NOP, call this function only to prevent compile warning.
    _fake_func_verify_defines();

    mm_cli_idx = LM_RESOURCE_NDIS;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_NDIS);

    toe_info = &pdev->toe_info;
    LM_TOE_FOREACH_TSS_IDX(pdev, i)
    {
        /* allocate SCQs */
        bd_chain = &toe_info->scqs[i].bd_chain;
        mem_size = pdev->params.l4_scq_page_cnt * LM_PAGE_SIZE;
        bd_chain->bd_chain_virt = mm_alloc_phys_mem(pdev, mem_size, &bd_chain->bd_chain_phy, 0, mm_cli_idx);
        if (!bd_chain->bd_chain_virt) {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }
        mm_memset(bd_chain->bd_chain_virt, 0, mem_size);
    }

    LM_TOE_FOREACH_RSS_IDX(pdev, i)
    {
        /* allocate RCQs */
        bd_chain = &toe_info->rcqs[i].bd_chain;
        mem_size = pdev->params.l4_rcq_page_cnt * LM_PAGE_SIZE;
        bd_chain->bd_chain_virt = mm_alloc_phys_mem(pdev, mem_size, &bd_chain->bd_chain_phy, 0, mm_cli_idx);
        if (!bd_chain->bd_chain_virt) {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }
        mm_memset(bd_chain->bd_chain_virt, 0, mem_size);

        /* allocate GRQs */
        bd_chain = &toe_info->grqs[i].bd_chain;
        mem_size = pdev->params.l4_grq_page_cnt * LM_PAGE_SIZE;
        bd_chain->bd_chain_virt = mm_alloc_phys_mem(pdev, mem_size, &bd_chain->bd_chain_phy, 0, mm_cli_idx);
        if (!bd_chain->bd_chain_virt) {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }
        mm_memset(bd_chain->bd_chain_virt, 0, mem_size);

        DbgBreakIf(toe_info->grqs[i].isles_pool);
        if (!pdev->params.l4_isles_pool_size) {
            pdev->params.l4_isles_pool_size = 2 * T_TCP_ISLE_ARRAY_SIZE;
        } else if (pdev->params.l4_isles_pool_size < T_TCP_ISLE_ARRAY_SIZE) {
            pdev->params.l4_isles_pool_size = T_TCP_ISLE_ARRAY_SIZE;
        }
        mem_size = pdev->params.l4_isles_pool_size * sizeof(lm_isle_t);
        toe_info->grqs[i].isles_pool = (lm_isle_t*)mm_alloc_mem(pdev, mem_size, mm_cli_idx);
        if (!toe_info->grqs[i].isles_pool) {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }
        mm_memset(toe_info->grqs[i].isles_pool, 0, mem_size);
    }
    if (pdev->params.l4_data_integrity) {
        u32_t pb_idx;
        pdev->toe_info.integrity_info.pattern_size = 256;
        pdev->toe_info.integrity_info.pattern_buf_size = 0x10000 + pdev->toe_info.integrity_info.pattern_size;
        pdev->toe_info.integrity_info.pattern_buf = mm_alloc_mem(pdev, pdev->toe_info.integrity_info.pattern_buf_size, mm_cli_idx);
        if (!pdev->toe_info.integrity_info.pattern_buf) {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }
        for (pb_idx = 0; pb_idx < pdev->toe_info.integrity_info.pattern_buf_size; pb_idx++) {
            pdev->toe_info.integrity_info.pattern_buf[pb_idx] = pb_idx %  pdev->toe_info.integrity_info.pattern_size;
        }
    }

    /* Allocate rss-update physical data */
    pdev->toe_info.rss_update_data = (struct toe_rss_update_ramrod_data *)
                                      mm_alloc_phys_mem(pdev, sizeof(*pdev->toe_info.rss_update_data),
                                                        &pdev->toe_info.rss_update_data_phys,
                                                        0,0);

    if (pdev->toe_info.rss_update_data == NULL)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }

    return LM_STATUS_SUCCESS;
}

static void _lm_get_default_l4cli_params(lm_device_t *pdev, l4_ofld_params_t *l4_params)
{
    lm_params_t *def_params = &pdev->params;

    DbgBreakIf(def_params->l4cli_ack_frequency > 0xff);
    l4_params->ack_frequency = def_params->l4cli_ack_frequency & 0xff;

    DbgBreakIf(def_params->l4cli_delayed_ack_ticks > 0xff);
    l4_params->delayed_ack_ticks = def_params->l4cli_delayed_ack_ticks & 0xff;

    DbgBreakIf(def_params->l4cli_doubt_reachability_retx > 0xff);
    l4_params->doubt_reachability_retx = def_params->l4cli_doubt_reachability_retx & 0xff;

    l4_params->dup_ack_threshold = def_params->l4cli_dup_ack_threshold;

    DbgBreakIf((def_params->l4cli_flags != 0) &&
               (def_params->l4cli_flags != OFLD_PARAM_FLAG_SNAP_ENCAP));
    l4_params->flags = def_params->l4cli_flags;

    DbgBreakIf(def_params->l4cli_max_retx > 0xff);
    l4_params->max_retx = def_params->l4cli_max_retx & 0xff;

    l4_params->nce_stale_ticks = def_params->l4cli_nce_stale_ticks;
    l4_params->push_ticks = def_params->l4cli_push_ticks;

    DbgBreakIf(def_params->l4cli_starting_ip_id > 0xffff);
    l4_params->starting_ip_id = def_params->l4cli_starting_ip_id & 0xffff;

    l4_params->sws_prevention_ticks = def_params->l4cli_sws_prevention_ticks;
    l4_params->ticks_per_second = def_params->l4cli_ticks_per_second;

}

/** Description
 *  requests generic buffers from the generic buffer pool and attaches the generic buffers
 *  to the grq-bd chain. It attaches the amount of buffers received, no matter if they were
 *  less than requested. Function always tries to fill bd-chain (i.e. requests bd_chain->bd_left)
 * Assumptions:
 *  - called after the generic buffer pool is ready to deliver generic buffers
 *  - who ever will call this function will handle checking if a work item for allocating more
 *    buffers is needed.
 * Returns:
 *  - TRUE: buffers were written
 *  - FALSE: o/w
 */
u8_t lm_tcp_rx_fill_grq(struct _lm_device_t * pdev, u8_t sb_idx, d_list_t * bypass_gen_pool_list, u8_t filling_mode)
{
    lm_toe_info_t        * toe_info;
    lm_tcp_grq_t         * grq;
    struct toe_rx_grq_bd * grq_bd;
    lm_tcp_gen_buf_t     * curr_gen_buf;
    lm_bd_chain_t        * bd_chain;
    d_list_t               tmp_gen_buf_list;
    d_list_t               free_gen_buf_list;
    u16_t                  num_bufs; /* limited by bd_chain->bd_left */
    u16_t                  num_bufs_threshold;
    u32_t                  num_bypass_buffs;
    u32_t                  avg_dpc_cnt;

    toe_info = &pdev->toe_info;
    grq      = &toe_info->grqs[sb_idx];
    bd_chain = &grq->bd_chain;
    num_bufs = bd_chain->bd_left; /* required number of bufs from grq pool */

    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_fill_grq bd_left (to be filled)= %d\n", bd_chain->bd_left);

    if (!pdev->params.l4_grq_filling_threshold_divider) {
        num_bufs_threshold = 1;
    } else {
        if (pdev->params.l4_grq_filling_threshold_divider < 2) {
            pdev->params.l4_grq_filling_threshold_divider = 2;
        }
        num_bufs_threshold = bd_chain->capacity / pdev->params.l4_grq_filling_threshold_divider;
    }

    d_list_init(&tmp_gen_buf_list, NULL, NULL, 0);
    d_list_init(&free_gen_buf_list, NULL, NULL, 0);
    if (bypass_gen_pool_list != NULL) {
        num_bypass_buffs = d_list_entry_cnt(bypass_gen_pool_list);
    } else {
        num_bypass_buffs = 0;
    }

    if (filling_mode == FILL_GRQ_MIN_CASHED_BDS) {
        u16_t bufs_in_chain = bd_chain->capacity - num_bufs;
        if (bufs_in_chain >= USTORM_TOE_GRQ_CACHE_NUM_BDS) {
            return 0;
        } else {
            num_bufs = USTORM_TOE_GRQ_CACHE_NUM_BDS - bufs_in_chain;
        }
    } else if (filling_mode == FILL_GRQ_LOW_THRESHOLD) {
        u16_t bufs_in_chain = bd_chain->capacity - num_bufs;
        DbgBreakIf(grq->low_bds_threshold < USTORM_TOE_GRQ_CACHE_NUM_BDS);
        if (grq->low_bds_threshold < USTORM_TOE_GRQ_CACHE_NUM_BDS) {
            grq->low_bds_threshold = 3*GRQ_XOFF_TH;
        }
        if (bufs_in_chain >= grq->low_bds_threshold) {
            return 0;
        } else {
            num_bufs = grq->low_bds_threshold - bufs_in_chain;
        }
    } else {
        if (grq->high_bds_threshold) {
            u16_t bufs_in_chain = bd_chain->capacity - num_bufs;
            if (bufs_in_chain >= grq->high_bds_threshold) {
                return 0;
            } else {
                num_bufs = grq->high_bds_threshold - bufs_in_chain;
            }
        }
        if (num_bufs < num_bufs_threshold) {
            if (num_bufs > num_bypass_buffs) {
                num_bufs = (u16_t)num_bypass_buffs; /* Partly fill grq from bypass only*/
                grq->gen_bufs_compensated_from_bypass_only += num_bypass_buffs;
            }
            if (!num_bufs) {
                return 0; /* nothing to fill or to fill later and more
                            to avoid abundant GEN_POOL_LOCK acquiring*/
            }
        }
    }

    if (num_bypass_buffs < num_bufs) {
        /* we can safely cast the returned value since we know we ask for max 2^16 */
        u16_t num_required_buffs = num_bufs - num_bypass_buffs;
        mm_tcp_get_gen_bufs(pdev, &tmp_gen_buf_list, num_required_buffs, sb_idx);
    }
    while ((d_list_entry_cnt(&tmp_gen_buf_list) < num_bufs) && num_bypass_buffs) {
		lm_tcp_gen_buf_t * tmp_buf = NULL;
        d_list_entry_t * curr_entry = d_list_pop_head(bypass_gen_pool_list);
		tmp_buf = (lm_tcp_gen_buf_t *)curr_entry;
        DbgBreakIf(!curr_entry);
		if (tmp_buf->flags & GEN_FLAG_FREE_WHEN_DONE)
		{
			d_list_push_head(&free_gen_buf_list, curr_entry);
		}
		else
		{
            d_list_push_head(&tmp_gen_buf_list, curr_entry);
		}
        num_bypass_buffs--;
    }
    num_bufs = (u16_t)d_list_entry_cnt(&tmp_gen_buf_list);
	if ((bypass_gen_pool_list != NULL) && d_list_entry_cnt(&free_gen_buf_list))
	{
		d_list_add_tail(bypass_gen_pool_list, &free_gen_buf_list);
	}
    /* stats... */
    grq->num_grqs_last_dpc = num_bufs;
    if (grq->num_grqs_last_dpc) {  /* Exclude zeroed value from statistics*/
        if (grq->num_grqs_last_dpc > grq->max_grqs_per_dpc) {
            grq->max_grqs_per_dpc = grq->num_grqs_last_dpc;
        }
        /* we don't want to wrap around...*/
        if ((grq->sum_grqs_last_x_dpcs + grq->num_grqs_last_dpc) < grq->sum_grqs_last_x_dpcs) {
            grq->avg_dpc_cnt = 0;
            grq->sum_grqs_last_x_dpcs = 0;
        }
        grq->sum_grqs_last_x_dpcs += grq->num_grqs_last_dpc;
        grq->avg_dpc_cnt++;
        avg_dpc_cnt = grq->avg_dpc_cnt;
        if (avg_dpc_cnt) { /*Prevent division by 0*/
            grq->avg_grqs_per_dpc = grq->sum_grqs_last_x_dpcs / avg_dpc_cnt;
        } else {
            grq->sum_grqs_last_x_dpcs = 0;
        }
    }

    DbgBreakIf(num_bufs != tmp_gen_buf_list.cnt);

    if (num_bufs < bd_chain->bd_left) {
        grq->num_deficient++;
    }

    if (!num_bufs) {
        DbgMessage(pdev, WARNl4rx, "no buffers returned from generic pool\n");
        return 0; /* nothing to do */
    }
    curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_head(&tmp_gen_buf_list);

    if (filling_mode == FILL_GRQ_LOW_THRESHOLD) {
        grq->gen_bufs_compensated_till_low_threshold += num_bufs;
    }
    while (num_bufs--) {
        DbgBreakIf(SIG(curr_gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
        DbgMessage(pdev, VERBOSEl4rx, "curr_gen_buf->buf_virt=0x%p, END_SIG=0x%x\n", curr_gen_buf->buf_virt,
                    END_SIG(curr_gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)));
        DbgBreakIf(END_SIG(curr_gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);

        /* initialize curr_gen_buf */
        curr_gen_buf->ind_bytes    = 0;
        curr_gen_buf->ind_nbufs    = 0;
        curr_gen_buf->placed_bytes = 0;
        curr_gen_buf->refcnt       = 0;
        curr_gen_buf->tcp          = NULL;

        grq_bd = (struct toe_rx_grq_bd *)lm_toe_bd_chain_produce_bd(bd_chain);
        DbgBreakIf(!grq_bd);
        /* attach gen buf to grq */
		DbgBreakIf(!curr_gen_buf || !curr_gen_buf->buf_phys.as_u64);
        grq_bd->addr_hi = curr_gen_buf->buf_phys.as_u32.high;
        grq_bd->addr_lo = curr_gen_buf->buf_phys.as_u32.low;

        curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_next_entry(&curr_gen_buf->link);
        /* enlist gen buf to active list will be done at the end of the loop (more efficient) */
    }

    if (bd_chain->bd_left) {
        DbgMessage(pdev, INFORMl4rx, "GRQ bd-chain wasn't filled completely\n");
    }
	if (d_list_entry_cnt(&tmp_gen_buf_list))
	{
        d_list_add_tail(&grq->active_gen_list, &tmp_gen_buf_list);
	}
    return (tmp_gen_buf_list.cnt != 0); /* how many buffers were actually placed */
}

/* Desciption:
 *  initialize l4 VBD resources
 * Assumptions:
 *  - lm_init_params was already called
 *  - lm_tcp_alloc_resc was already called
 *  - um GRQ pool is ready to supply buffers to lm (?)
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_tcp_init_resc(struct _lm_device_t *pdev, u8_t b_is_init )
{
    lm_toe_info_t *toe_info;
    lm_bd_chain_t *bd_chain;
    long i;
    u16_t volatile * sb_indexes;
    u32_t sb_id;

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_init_resc\n");
    toe_info = &pdev->toe_info;
    toe_info->state = LM_TOE_STATE_INIT;

    /* init rest of toe_info fields */
    toe_info->rss_update_cnt = 0;
    toe_info->gen_buf_size = lm_tcp_calc_gen_buf_size(pdev);
    LM_TCP_SET_UPDATE_WINDOW_MODE(pdev, LM_TOE_UPDATE_MODE_SHORT_LOOP);

    if( b_is_init )
    {
        d_list_init(&toe_info->state_blk.neigh_list, NULL, NULL, 0);
        d_list_init(&toe_info->state_blk.path_list, NULL, NULL, 0);
        d_list_init(&toe_info->state_blk.tcp_list, NULL, NULL, 0);
    }

    /* TODO: consider enabling the assertion */
    //DbgBreakIf(pdev->ofld_info.state_blks[STATE_BLOCK_TOE]);
    pdev->ofld_info.state_blks[STATE_BLOCK_TOE] = &toe_info->state_blk;

    LM_TOE_FOREACH_TSS_IDX(pdev, i)
    {
        /* init SCQs */
        lm_tcp_scq_t *scq = &toe_info->scqs[i];
        bd_chain = &scq->bd_chain;
        lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt,
                          bd_chain->bd_chain_phy, (u16_t)pdev->params.l4_scq_page_cnt, sizeof(struct toe_tx_cqe), 1, TRUE);
        /* Assign the SCQ chain consumer pointer to the consumer index in the status block. */
        sb_id = RSS_ID_TO_SB_ID(i);
#ifdef _VBD_
	if (!CHIP_IS_E1x(pdev) && (pdev->params.l4_enable_rss == L4_RSS_DISABLED)) 
	{
            sb_id = LM_NON_RSS_SB(pdev);
	}
#endif
        sb_indexes = lm_get_sb_indexes(pdev, (u8_t)sb_id);
        sb_indexes[HC_INDEX_TOE_TX_CQ_CONS] = 0;
        scq->hw_con_idx_ptr = sb_indexes + HC_INDEX_TOE_TX_CQ_CONS;
        scq->hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_TYPE;
        scq->hc_sb_info.hc_index_value = HC_INDEX_TOE_TX_CQ_CONS;
    }


    /* Before initializing GRQs, we need to check if there are left-overs from before (incase this isn't the iniitiali 'init', for that we need to clear
     * them - but outside the loop... */
    if ( !b_is_init ) {
        /* we need to return what ever buffers are still on the grq back to the pool before
         * the new initialization... */
         lm_tcp_clear_grqs(pdev);
    }

    LM_TOE_FOREACH_RSS_IDX(pdev, i)
    {
        lm_tcp_rcq_t *rcq = &toe_info->rcqs[i];
        lm_tcp_grq_t *grq = &toe_info->grqs[i];
	u8_t byte_counter_id;

	sb_id = RSS_ID_TO_SB_ID(i);
#ifdef _VBD_
	if (!CHIP_IS_E1x(pdev) && (pdev->params.l4_enable_rss == L4_RSS_DISABLED)) 
	{
	    sb_id = LM_NON_RSS_SB(pdev);
	}
#endif
	byte_counter_id = CHIP_IS_E1x(pdev)? LM_FW_SB_ID(pdev, sb_id) : LM_FW_DHC_QZONE_ID(pdev, sb_id);

        /* init RCQs */
        bd_chain = &rcq->bd_chain;
        lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt,
                          bd_chain->bd_chain_phy, (u16_t)pdev->params.l4_rcq_page_cnt, sizeof(struct toe_rx_cqe), 1, TRUE);
        rcq->rss_update_pending = 0;
        rcq->suspend_processing = FALSE;
        rcq->update_cid = 0;

        /* Assign the RCQ chain consumer pointer to the consumer index in the status block. */
        sb_indexes = lm_get_sb_indexes(pdev, (u8_t)sb_id);
        sb_indexes[HC_INDEX_TOE_RX_CQ_CONS] = 0;
        rcq->hw_con_idx_ptr = sb_indexes + HC_INDEX_TOE_RX_CQ_CONS;
        rcq->hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_SL_TYPE;
        rcq->hc_sb_info.hc_index_value = HC_INDEX_TOE_RX_CQ_CONS;
        if (IS_PFDEV(pdev))
        {
            rcq->hc_sb_info.iro_dhc_offset = CSTORM_BYTE_COUNTER_OFFSET(byte_counter_id, HC_INDEX_TOE_RX_CQ_CONS);
        }
        else
        {
            DbgMessage(pdev, FATAL, "Dhc not implemented for VF yet\n");
        }

        /* init GRQs */
        if( b_is_init )
        {
            d_list_init(&grq->active_gen_list, NULL, NULL, 0);
            d_list_init(&grq->aux_gen_list, NULL, NULL, 0);
            if ((u8_t)i != LM_TOE_BASE_RSS_ID(pdev)  ) {
                grq->grq_compensate_on_alloc = TRUE;
                pdev->toe_info.grqs[i].high_bds_threshold = 3*GRQ_XOFF_TH + 1;
            } else {
                grq->grq_compensate_on_alloc = FALSE;
                pdev->toe_info.grqs[i].high_bds_threshold = 0;
            }
            grq->low_bds_threshold = 3*GRQ_XOFF_TH;
        }

        bd_chain = &grq->bd_chain;
        lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt,
                          bd_chain->bd_chain_phy, (u16_t)pdev->params.l4_grq_page_cnt, sizeof(struct toe_rx_grq_bd), 0, TRUE);
        /* fill GRQ (minimum mode)*/
        lm_tcp_rx_fill_grq(pdev, (u8_t)i, NULL, FILL_GRQ_MIN_CASHED_BDS);
    }


    LM_TOE_FOREACH_RSS_IDX(pdev, i)
    {
        // lm_tcp_grq_t *grq = &toe_info->grqs[i];
        lm_tcp_rx_fill_grq(pdev, (u8_t)i, NULL, FILL_GRQ_FULL);
    }

    return LM_STATUS_SUCCESS;
}


/* init cstorm internal memory for toe
 * assumption - strom's common intmem (if any) already initiated */
static void _lm_tcp_init_cstorm_intmem(lm_device_t *pdev)
{
    lm_toe_info_t *toe_info;
    lm_address_t phys_addr;
    lm_tcp_scq_t *scq;
    u16_t idx;
    u8_t drv_toe_rss_id;
    u8_t port;
    u8_t fw_sb_id;

    toe_info = &pdev->toe_info;
    port = PORT_ID(pdev);

    LM_TOE_FOREACH_TSS_IDX(pdev, drv_toe_rss_id)
    {
        scq = &toe_info->scqs[drv_toe_rss_id];

        /* SCQ consumer ptr - scq first page addr */
        phys_addr = lm_bd_chain_phys_addr(&scq->bd_chain, 0);
        DbgBreakIf(CSTORM_TOE_CQ_CONS_PTR_LO_SIZE != 4);

        LM_INTMEM_WRITE32(pdev, CSTORM_TOE_CQ_CONS_PTR_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.low, BAR_CSTRORM_INTMEM);

        DbgBreakIf (CSTORM_TOE_CQ_CONS_PTR_HI_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, CSTORM_TOE_CQ_CONS_PTR_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.high, BAR_CSTRORM_INTMEM);

        /* SCQ producer idx */
        idx = lm_bd_chain_prod_idx(&scq->bd_chain);

        DbgBreakIf(CSTORM_TOE_CQ_PROD_SIZE != 2);
        LM_INTMEM_WRITE16(pdev, CSTORM_TOE_CQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), idx, BAR_CSTRORM_INTMEM);

        /* SCQ consumer idx */
        idx = lm_bd_chain_cons_idx(&scq->bd_chain);
        DbgBreakIf(idx != 0);

        DbgBreakIf(CSTORM_TOE_CQ_CONS_SIZE != 2);
        LM_INTMEM_WRITE16(pdev, CSTORM_TOE_CQ_CONS_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), idx, BAR_CSTRORM_INTMEM);

        /* SCQ second page addr */
        phys_addr = lm_bd_chain_phys_addr(&scq->bd_chain, 1);

        DbgBreakIf(CSTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_LO_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, CSTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.low, BAR_CSTRORM_INTMEM);

        DbgBreakIf(CSTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_HI_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, CSTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.high, BAR_CSTRORM_INTMEM);

        DbgBreakIf(CSTORM_TOE_CQ_NXT_PAGE_ADDR_VALID_SIZE != 1);

        LM_INTMEM_WRITE8(pdev, CSTORM_TOE_CQ_NXT_PAGE_ADDR_VALID_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), 1, BAR_CSTRORM_INTMEM);

        //LM_INTMEM_WRITE8(pdev, CSTORM_TOE_STATUS_BLOCK_ID_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), BAR_CSTRORM_INTMEM);
	fw_sb_id = LM_FW_SB_ID(pdev, RSS_ID_TO_SB_ID(drv_toe_rss_id));
#ifdef _VBD_
	if (!CHIP_IS_E1x(pdev) && (pdev->params.l4_enable_rss == L4_RSS_DISABLED)) 
	{
		fw_sb_id = LM_FW_SB_ID(pdev, RSS_ID_TO_SB_ID(LM_NON_RSS_SB(pdev)));
		if (drv_toe_rss_id != LM_NON_RSS_CHAIN(pdev)) 
		{
			DbgBreak();
		}
	}
#endif
        LM_INTMEM_WRITE8(pdev, CSTORM_TOE_STATUS_BLOCK_ID_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), fw_sb_id, BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE8(pdev, CSTORM_TOE_STATUS_BLOCK_INDEX_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), HC_INDEX_TOE_TX_CQ_CONS, BAR_CSTRORM_INTMEM);
    }
}

/* init ustorm offload params private to TOE */
static void _lm_set_ofld_params_ustorm_toe(lm_device_t *pdev, l4_ofld_params_t *l4_params)
{
    u8_t func;
    u32_t val32;

    func = FUNC_ID(pdev);

    /* global push timer ticks */
    /* This value is in milliseconds instead of ticks in SNP
     * and Longhorn.  In the future microsoft will change these
     * values to ticks. TBA : When fix takes place, uncomment first line and remove second line */
    /* val32 = lm_time_resolution(pdev, l4_params->push_ticks, l4_params->ticks_per_second, 1000); */
    val32 = lm_time_resolution(pdev, l4_params->push_ticks, 1000, 1000);

    DbgBreakIf (USTORM_TOE_TCP_PUSH_TIMER_TICKS_SIZE != 4);
    LM_INTMEM_WRITE32(pdev, USTORM_TOE_TCP_PUSH_TIMER_TICKS_OFFSET(func), val32, BAR_USTRORM_INTMEM);
}

/* init ustorm internal memory for toe
 * assumption - strom's common intmem (if any) already initiated */
static void _lm_tcp_init_ustorm_intmem(lm_device_t *pdev)
{
    lm_toe_info_t *toe_info;
    lm_address_t phys_addr;
    lm_tcp_rcq_t *rcq;
    lm_tcp_grq_t *grq;
    struct toe_rx_grq_bd *grq_bd;
    u16_t idx;
    u8_t drv_toe_rss_id, grq_bd_idx;
    u8_t port;
    u8_t fw_sb_id;
    u8_t sw_sb_id;

    toe_info = &pdev->toe_info;
    port = PORT_ID(pdev);

    _lm_set_ofld_params_ustorm_toe(pdev, &(pdev->ofld_info.l4_params));

    LM_TOE_FOREACH_RSS_IDX(pdev,drv_toe_rss_id)
    {

        rcq = &toe_info->rcqs[drv_toe_rss_id];
        grq = &toe_info->grqs[drv_toe_rss_id];

        /* GRQ cache bds */
        grq_bd = (struct toe_rx_grq_bd *)grq->bd_chain.bd_chain_virt;

        DbgBreakIf( USTORM_TOE_GRQ_CACHE_NUM_BDS > lm_bd_chain_usable_bds_per_page(&grq->bd_chain));

        for(grq_bd_idx = 0; grq_bd_idx < USTORM_TOE_GRQ_CACHE_NUM_BDS; grq_bd_idx++) {
            LM_INTMEM_WRITE32(pdev, USTORM_GRQ_CACHE_BD_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id) ,port,grq_bd_idx), grq_bd->addr_lo, BAR_USTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev, USTORM_GRQ_CACHE_BD_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id),port,grq_bd_idx), grq_bd->addr_hi, BAR_USTRORM_INTMEM);
            grq_bd++;
        }

        /* GRQ cache prod idx */
        DbgBreakIf (USTORM_TOE_GRQ_LOCAL_PROD_SIZE != 1);
        LM_INTMEM_WRITE8(pdev, USTORM_TOE_GRQ_LOCAL_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port),  (u8_t)USTORM_TOE_GRQ_CACHE_NUM_BDS, BAR_USTRORM_INTMEM);

        /* GRQ cache cons idx */
        DbgBreakIf (USTORM_TOE_GRQ_LOCAL_CONS_SIZE != 1);
        LM_INTMEM_WRITE8(pdev, USTORM_TOE_GRQ_LOCAL_CONS_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port),  0, BAR_USTRORM_INTMEM);

        /* GRQ producer idx */
        idx = lm_bd_chain_prod_idx(&grq->bd_chain);
        DbgBreakIf (USTORM_TOE_GRQ_PROD_SIZE != 2);
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_GRQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), idx, BAR_USTRORM_INTMEM);

        /* GRQ consumer idx */
        DbgBreakIf (USTORM_TOE_GRQ_CONS_SIZE != 2);
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_GRQ_CONS_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), (u8_t)USTORM_TOE_GRQ_CACHE_NUM_BDS, BAR_USTRORM_INTMEM);

        /* GRQ consumer ptr */
        phys_addr = lm_bd_chain_phys_addr(&grq->bd_chain, 0);
        LM_INC64(&phys_addr, sizeof(struct toe_rx_grq_bd) * USTORM_TOE_GRQ_CACHE_NUM_BDS);

        DbgBreakIf (USTORM_TOE_GRQ_CONS_PTR_LO_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, USTORM_TOE_GRQ_CONS_PTR_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.low, BAR_USTRORM_INTMEM);

        DbgBreakIf (USTORM_TOE_GRQ_CONS_PTR_HI_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, USTORM_TOE_GRQ_CONS_PTR_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.high, BAR_USTRORM_INTMEM);

        /* Generic buffer size */
        DbgBreakIf (USTORM_TOE_GRQ_BUF_SIZE_SIZE != 2);

        DbgBreakIf(LM_TCP_GEN_BUF_SIZE(pdev) > 0xffff); /* the size available in ustorm */
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_GRQ_BUF_SIZE_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), (u16_t)LM_TCP_GEN_BUF_SIZE(pdev), BAR_USTRORM_INTMEM);

        /* RCQ consumer ptr - rcq first page addr */
        phys_addr = lm_bd_chain_phys_addr(&rcq->bd_chain, 0);

        DbgBreakIf (USTORM_TOE_CQ_CONS_PTR_LO_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, USTORM_TOE_CQ_CONS_PTR_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.low, BAR_USTRORM_INTMEM);

        DbgBreakIf (USTORM_TOE_CQ_CONS_PTR_HI_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, USTORM_TOE_CQ_CONS_PTR_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.high, BAR_USTRORM_INTMEM);

        /* RCQ second page addr */
        phys_addr = lm_bd_chain_phys_addr(&rcq->bd_chain, 1);

        DbgBreakIf (USTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_LO_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, USTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.low, BAR_USTRORM_INTMEM);

        DbgBreakIf (USTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_HI_SIZE != 4);
        LM_INTMEM_WRITE32(pdev, USTORM_TOE_CQ_NEXT_PAGE_BASE_ADDR_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), phys_addr.as_u32.high, BAR_USTRORM_INTMEM);

        DbgBreakIf (USTORM_TOE_CQ_NXT_PAGE_ADDR_VALID_SIZE != 1);
        LM_INTMEM_WRITE8(pdev, USTORM_TOE_CQ_NXT_PAGE_ADDR_VALID_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), 1, BAR_USTRORM_INTMEM);

        /* RCQ producer idx */
        idx = lm_bd_chain_prod_idx(&rcq->bd_chain);

        DbgBreakIf (USTORM_TOE_CQ_PROD_SIZE != 2);
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_CQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), idx, BAR_USTRORM_INTMEM);
        if (pdev->params.enable_dynamic_hc[HC_INDEX_TOE_RX_CQ_CONS]) {
            u32_t l4_quasi_byte_counter;
            u16_t prod_idx_diff = lm_bd_chain_prod_idx(&rcq->bd_chain) - rcq->bd_chain.bds_per_page * rcq->bd_chain.page_cnt;
            l4_quasi_byte_counter = prod_idx_diff;
            l4_quasi_byte_counter <<= 16;
//            LM_INTMEM_WRITE32(pdev, CSTORM_BYTE_COUNTER_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), HC_INDEX_TOE_RX_CQ_CONS), l4_quasi_byte_counter, BAR_CSTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev, rcq->hc_sb_info.iro_dhc_offset, l4_quasi_byte_counter, BAR_CSTRORM_INTMEM);
        }
        /* RCQ consumer idx */
        idx = lm_bd_chain_cons_idx(&rcq->bd_chain);
        DbgBreakIf(idx != 0);

        DbgBreakIf (USTORM_TOE_CQ_CONS_SIZE != 2);
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_CQ_CONS_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), idx, BAR_USTRORM_INTMEM);

        fw_sb_id = LM_FW_SB_ID(pdev, RSS_ID_TO_SB_ID(drv_toe_rss_id));
	sw_sb_id = RSS_ID_TO_SB_ID(drv_toe_rss_id);
        if (RSS_ID_TO_SB_ID(drv_toe_rss_id) >= MAX_NDSB) { //To suppress Prefast warning
            DbgBreak();
            break;
        }
#ifdef _VBD_
	if (!CHIP_IS_E1x(pdev) && (pdev->params.l4_enable_rss == L4_RSS_DISABLED)) 
	{
		fw_sb_id = LM_FW_SB_ID(pdev, RSS_ID_TO_SB_ID(LM_NON_RSS_SB(pdev)));
		sw_sb_id = LM_NON_RSS_SB(pdev);
		if (drv_toe_rss_id != LM_NON_RSS_CHAIN(pdev)) 
		{
			DbgBreak();
		}
	}
#endif
        if (CHIP_IS_E1x(pdev)) {

            if (pdev->params.enable_dynamic_hc[HC_INDEX_TOE_RX_CQ_CONS]) {
                pdev->vars.status_blocks_arr[RSS_ID_TO_SB_ID(drv_toe_rss_id)].hc_status_block_data.e1x_sb_data.index_data[HC_INDEX_TOE_RX_CQ_CONS].flags |= HC_INDEX_DATA_DYNAMIC_HC_ENABLED;
            } else {
                pdev->vars.status_blocks_arr[RSS_ID_TO_SB_ID(drv_toe_rss_id)].hc_status_block_data.e1x_sb_data.index_data[HC_INDEX_TOE_RX_CQ_CONS].flags &= ~HC_INDEX_DATA_DYNAMIC_HC_ENABLED;
            }
            LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id)
                              + OFFSETOF(struct hc_status_block_data_e1x, index_data)
                              + sizeof(struct hc_index_data)*HC_INDEX_TOE_RX_CQ_CONS
                              + OFFSETOF(struct hc_index_data,flags),
                              pdev->vars.status_blocks_arr[RSS_ID_TO_SB_ID(drv_toe_rss_id)].hc_status_block_data.e1x_sb_data.index_data[HC_INDEX_ETH_RX_CQ_CONS].flags, BAR_CSTRORM_INTMEM);
        } else {

            if (pdev->params.enable_dynamic_hc[HC_INDEX_TOE_RX_CQ_CONS]) {
                pdev->vars.status_blocks_arr[sw_sb_id].hc_status_block_data.e2_sb_data.index_data[HC_INDEX_TOE_RX_CQ_CONS].flags |= HC_INDEX_DATA_DYNAMIC_HC_ENABLED;
            } else {
                pdev->vars.status_blocks_arr[sw_sb_id].hc_status_block_data.e2_sb_data.index_data[HC_INDEX_TOE_RX_CQ_CONS].flags &= ~HC_INDEX_DATA_DYNAMIC_HC_ENABLED;
            }
            LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id)
                              + OFFSETOF(struct hc_status_block_data_e2, index_data)
                              + sizeof(struct hc_index_data)*HC_INDEX_TOE_RX_CQ_CONS
                              + OFFSETOF(struct hc_index_data,flags),
                              pdev->vars.status_blocks_arr[sw_sb_id].hc_status_block_data.e2_sb_data.index_data[HC_INDEX_ETH_RX_CQ_CONS].flags, BAR_CSTRORM_INTMEM);

        }

//        LM_INTMEM_WRITE8(pdev, USTORM_TOE_STATUS_BLOCK_ID_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port),LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), BAR_USTRORM_INTMEM);
        LM_INTMEM_WRITE8(pdev, USTORM_TOE_STATUS_BLOCK_ID_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port),fw_sb_id, BAR_USTRORM_INTMEM);
        LM_INTMEM_WRITE8(pdev, USTORM_TOE_STATUS_BLOCK_INDEX_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id), port), HC_INDEX_TOE_RX_CQ_CONS, BAR_USTRORM_INTMEM);
    }

    /* Initialize Indirection Table : Only in entries that match status - blocks : L4 base--> L4 base + cnt */
    DbgBreakIf (USTORM_INDIRECTION_TABLE_ENTRY_SIZE != 1);

    if (pdev->params.l4_enable_rss == L4_RSS_DISABLED) {
        LM_TOE_FOREACH_RSS_IDX(pdev, idx)
        {
            LM_INTMEM_WRITE8(pdev, USTORM_INDIRECTION_TABLE_OFFSET(port) + LM_TOE_FW_RSS_ID(pdev,idx), LM_TOE_FW_RSS_ID(pdev,(u8_t)idx), BAR_USTRORM_INTMEM);
        }
    } else {
        for (idx = 0; idx < RSS_INDIRECTION_TABLE_SIZE; idx++) {
            LM_INTMEM_WRITE8(pdev,USTORM_INDIRECTION_TABLE_OFFSET(port) + idx, pdev->toe_info.indirection_table[idx], BAR_USTRORM_INTMEM);
        }
    }
}

/* init tstorm offload params common to TOE/RDMA/ISCSI */
static void _lm_set_ofld_params_tstorm_common(lm_device_t *pdev, l4_ofld_params_t *l4_params)
{
    u8_t func;
    u32_t dup_ack_threshold;

    func = FUNC_ID(pdev);

    dup_ack_threshold = l4_params->dup_ack_threshold;
    if(dup_ack_threshold > TCP_TSTORM_MAX_DUP_ACK_TH) {
        DbgMessage(pdev, WARNl4sp,
                   "given dup_ack_threshold (=%d) too high. setting it to maximum allowed (=%d)\n",
                   dup_ack_threshold, TCP_TSTORM_MAX_DUP_ACK_TH);
        dup_ack_threshold = TCP_TSTORM_MAX_DUP_ACK_TH;
    }

    DbgBreakIf (TSTORM_TCP_DUPLICATE_ACK_THRESHOLD_SIZE != 4);
    LM_INTMEM_WRITE32(pdev, TSTORM_TCP_DUPLICATE_ACK_THRESHOLD_OFFSET(func), dup_ack_threshold, BAR_TSTRORM_INTMEM);

    /* MaxCwnd  */
    DbgBreakIf (TSTORM_TCP_MAX_CWND_SIZE != 4);
    if(pdev->params.network_type == LM_NETOWRK_TYPE_WAN) {
        LM_INTMEM_WRITE32(pdev, TSTORM_TCP_MAX_CWND_OFFSET(func), pdev->params.max_cwnd_wan, BAR_TSTRORM_INTMEM);
    } else {
        DbgBreakIf(pdev->params.network_type != LM_NETOWRK_TYPE_LAN);
        LM_INTMEM_WRITE32(pdev, TSTORM_TCP_MAX_CWND_OFFSET(func), pdev->params.max_cwnd_lan, BAR_TSTRORM_INTMEM);
    }
}

/* init tstorm offload params private to TOE */
static void _lm_set_ofld_params_tstorm_toe(lm_device_t *pdev, l4_ofld_params_t *l4_params)
{
    u8_t func;

    func = FUNC_ID(pdev);

    /* max retransmit (TOE param only) */
    DbgBreakIf (TSTORM_TOE_MAX_SEG_RETRANSMIT_SIZE != 4);
    LM_INTMEM_WRITE32(pdev, TSTORM_TOE_MAX_SEG_RETRANSMIT_OFFSET(func), l4_params->max_retx, BAR_TSTRORM_INTMEM);

    /* TcpDoubtReachability (TOE param only) */
    DbgBreakIf (TSTORM_TOE_DOUBT_REACHABILITY_SIZE != 1);
    LM_INTMEM_WRITE8(pdev, TSTORM_TOE_DOUBT_REACHABILITY_OFFSET(func), l4_params->doubt_reachability_retx, BAR_TSTRORM_INTMEM);

}

/* init tstorm internal memory for toe
 * assumption - strom's common intmem already initiated */
static void _lm_tcp_init_tstorm_intmem(lm_device_t *pdev)
{
    _lm_set_ofld_params_tstorm_toe(pdev, &(pdev->ofld_info.l4_params));

    DbgBreakIf (TSTORM_TOE_MAX_DOMINANCE_VALUE_SIZE != 1);
    LM_INTMEM_WRITE8(pdev, TSTORM_TOE_MAX_DOMINANCE_VALUE_OFFSET, (u8_t)pdev->params.l4_max_dominance_value, BAR_TSTRORM_INTMEM);
    DbgBreakIf (TSTORM_TOE_DOMINANCE_THRESHOLD_SIZE != 1);
    LM_INTMEM_WRITE8(pdev, TSTORM_TOE_DOMINANCE_THRESHOLD_OFFSET, (u8_t)pdev->params.l4_dominance_threshold, BAR_TSTRORM_INTMEM);

}


/* init xstorm offload params common to TOE/RDMA/ISCSI */
static void _lm_set_ofld_params_xstorm_common(lm_device_t *pdev, l4_ofld_params_t *l4_params)
{
    u8_t func, ack_frequency;
    u32_t val32, max_reg, tmr_reg, delayed_ack_ticks;

    func = FUNC_ID(pdev);
    if (PORT_ID(pdev)) {
        max_reg = XCM_REG_GLB_DEL_ACK_MAX_CNT_1;
        tmr_reg = XCM_REG_GLB_DEL_ACK_TMR_VAL_1;
    } else {
        max_reg = XCM_REG_GLB_DEL_ACK_MAX_CNT_0;
        tmr_reg = XCM_REG_GLB_DEL_ACK_TMR_VAL_0;
    }
    /* if ack_frequency is 0, it means use default value of 2. */
    /* delayed max ack count, (both in internal ram and in XCM!!!) */
    ack_frequency = l4_params->ack_frequency;
    if(ack_frequency < TCP_XCM_MIN_GLB_DEL_ACK_MAX_CNT) {
        DbgMessage(pdev, WARNl4sp,
                   "given ack_frequency (=%d) too low. setting it to minimum allowed (=%d)\n",
                   ack_frequency, TCP_XCM_DEFAULT_DEL_ACK_MAX_CNT);
        ack_frequency = TCP_XCM_DEFAULT_DEL_ACK_MAX_CNT;
    }


    DbgBreakIf (XSTORM_TCP_GLOBAL_DEL_ACK_COUNTER_MAX_COUNT_SIZE != 1);
    LM_INTMEM_WRITE8(pdev, XSTORM_TCP_GLOBAL_DEL_ACK_COUNTER_MAX_COUNT_OFFSET(func), ack_frequency, BAR_XSTRORM_INTMEM);
    REG_WR(pdev,  max_reg, ack_frequency);

    /* This value is in milliseconds instead of ticks in SNP
     * and Longhorn.  In the future microsoft will change these
     * values to ticks. TBA : When fix takes place, uncomment first line and remove second line */
    /* delayed_ack_ticks = lm_time_resolution(pdev, l4_params->delayed_ack_ticks, l4_params->ticks_per_second, 1000); */
    delayed_ack_ticks = lm_time_resolution(pdev, l4_params->delayed_ack_ticks, 1000, TIMERS_TICKS_PER_SEC);

    /* delayed ack timer */
    REG_WR(pdev,   tmr_reg, delayed_ack_ticks);

    /* sws timer */
    /* This value (sws_prevention_ticks) is in milliseconds instead of ticks in SNP
     * and Longhorn.  In the future microsoft will change these
     * values to ticks. TBA : When fix takes place, uncomment first line and remove second line */
    /* val32 = lm_time_resolution(pdev, l4_params->sws_prevention_ticks, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC); */
    val32 = lm_time_resolution(pdev, l4_params->sws_prevention_ticks, 1000 , TIMERS_TICKS_PER_SEC);

    DbgBreakIf (XSTORM_TCP_TX_SWS_TIMER_VAL_SIZE != 4);
    LM_INTMEM_WRITE32(pdev, XSTORM_TCP_TX_SWS_TIMER_VAL_OFFSET(func), val32, BAR_XSTRORM_INTMEM);

    DbgBreakIf (XSTORM_COMMON_RTC_RESOLUTION_SIZE != 2);
    LM_INTMEM_WRITE16(pdev, XSTORM_COMMON_RTC_RESOLUTION_OFFSET, 1000 / l4_params->ticks_per_second , BAR_XSTRORM_INTMEM);
}

/* init xstorm offload params private to TOE */
static void _lm_set_ofld_params_xstorm_toe(lm_device_t *pdev, l4_ofld_params_t *l4_params)
{
    u8_t func;

    func = FUNC_ID(pdev);

    DbgBreakIf (XSTORM_TOE_LLC_SNAP_ENABLED_SIZE != 1);
    if(l4_params->flags & OFLD_PARAM_FLAG_SNAP_ENCAP) {
        LM_INTMEM_WRITE8(pdev, XSTORM_TOE_LLC_SNAP_ENABLED_OFFSET(func), 1, BAR_XSTRORM_INTMEM);
    } else {
        LM_INTMEM_WRITE8(pdev, XSTORM_TOE_LLC_SNAP_ENABLED_OFFSET(func), 0, BAR_XSTRORM_INTMEM);
    }
}

/* init xstorm internal memory for toe
 * assumption - strom's common intmem already initiated */
static void _lm_tcp_init_xstorm_intmem(lm_device_t *pdev)
{
    _lm_set_ofld_params_xstorm_toe(pdev, &(pdev->ofld_info.l4_params));
}

/* Desciption:
 *  init chip internal memory and hw that is common for TOE, ISCSI and RDMA
 * Assumptions:
 *  - lm_init_params was already called
 * Returns:
 *  SUCCESS or any failure  */
lm_status_t lm_tcp_init_chip_common(lm_device_t *pdev)
{
    l4_ofld_params_t l4_params;
    u8_t func;

    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init_chip_common\n");
    DbgBreakIf(!pdev);

    func = FUNC_ID(pdev);

    _lm_get_default_l4cli_params(pdev, &l4_params);

    pdev->ofld_info.l4_params = l4_params;
    
    /* init common internal memory/hw for each storm
     * (c+u storms do not have common offload params) */
    _lm_set_ofld_params_xstorm_common(pdev, &l4_params);
    _lm_set_ofld_params_tstorm_common(pdev, &l4_params);


    /* init internal memory constatns (non-dependant on l4_params)*/

    /* enable delayed acks */
    DbgBreakIf (XSTORM_TCP_GLOBAL_DEL_ACK_COUNTER_ENABLED_SIZE != 1);
    LM_INTMEM_WRITE8(pdev, XSTORM_TCP_GLOBAL_DEL_ACK_COUNTER_ENABLED_OFFSET(func), 1 /* always enabled */, BAR_XSTRORM_INTMEM);

    /* ip id (init value currently constant: 0x8000) */
    DbgBreakIf (XSTORM_TCP_IPID_SIZE != 2);
    LM_INTMEM_WRITE16(pdev, XSTORM_TCP_IPID_OFFSET(func), TOE_XSTORM_IP_ID_INIT_HI, BAR_XSTRORM_INTMEM);

    return LM_STATUS_SUCCESS;
}

/* Desciption:
 *  init chip internal memory for L4
 * Returns:
 *  SUCCESS or any failure  */
lm_status_t lm_tcp_init_chip(lm_device_t *pdev)
{
    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_init_chip\n");

    /* GilR 4/9/2006 - TODO - Assaf - RSS indirection table default initialization, done in L2? */

    /* init XSTORM internal RAM */
    _lm_tcp_init_xstorm_intmem(pdev);

    /* init CSTORM internal RAM */
    _lm_tcp_init_cstorm_intmem(pdev);

    /* init TSTORM internal RAM */
    _lm_tcp_init_tstorm_intmem(pdev);

    /* init USTORM internal RAM */
    _lm_tcp_init_ustorm_intmem(pdev);

    return LM_STATUS_SUCCESS;
}

/* Desciption:
 *  send TOE START ramrod wait for completion and return
 * Assumptions:
 *  - there is no pending slow path request for the leading connection (cid=0)
 *  - interrupts are already enabled
 * Returns:
 *  SUCCESS or any failure  */
lm_status_t lm_tcp_start_chip(lm_device_t *pdev)
{
    lm_toe_info_t *toe_info;
    u32_t to_cnt = 100000; /* GilR 4/9/2006 - TBA - 'to_cnt' in lm_tcp_init_chip need to be removed? */
    u64_t data;
    struct toe_init_ramrod_data toe_init_data;

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_start_chip\n");

    toe_info = &pdev->toe_info;

    /* send TOE INIT ramrod and wait for completion */
    DbgBreakIf(toe_info->state != LM_TOE_STATE_INIT);

    toe_init_data.rss_num = LM_TOE_FW_RSS_ID(pdev,LM_TOE_BASE_RSS_ID(pdev));
    data = *((u64_t*)(&toe_init_data));
    lm_command_post(pdev, LM_SW_LEADING_RSS_CID(pdev), RAMROD_OPCODE_TOE_INIT, CMD_PRIORITY_NORMAL, TOE_CONNECTION_TYPE, data);
    while (toe_info->state != LM_TOE_STATE_NORMAL && to_cnt) {
        mm_wait(pdev,100);
        to_cnt--;
    }
    /* GilR 5/16/2006 - TODO - DbgBreakIf(toe_info->state != LM_TOE_STATE_NORMAL); commented out for windows user mode */
    if(toe_info->state != LM_TOE_STATE_NORMAL) {
#ifndef _VBD_CMD_
        DbgMessage(pdev, FATAL, "TOE init ramrod did not complete\n");
#else
        toe_info->state = LM_TOE_STATE_NORMAL;
        lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_INIT, TOE_CONNECTION_TYPE, LM_SW_LEADING_RSS_CID(pdev));
#endif

        #if defined(_VBD_)
        DbgBreak();
        #endif
    }

    /* cid recycled cb registration  */
    lm_cid_recycled_cb_register(pdev, TOE_CONNECTION_TYPE, lm_tcp_recycle_cid_cb);

    /* Sq-completion cb registration (sq that get completed internally in driver */
    lm_sq_comp_cb_register(pdev, TOE_CONNECTION_TYPE, lm_tcp_comp_cb);

    return LM_STATUS_SUCCESS;
}

/* Desciption:
 *  allocate and initiate l4 (lm driver and chip)
 * Assumptions:
 *  - lm_init_params was already called
 *  - um GRQ pool is ready to supply buffers to lm (?)
 *  - there is no pending slow path request for the leading connection (cid=0)
 *  - interrupts are already enabled
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_tcp_init(lm_device_t *pdev)
{
    lm_toe_info_t *toe_info;
    lm_status_t lm_status;

    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init\n");
    if (IS_VFDEV(pdev)) {
        DbgMessage(pdev, FATAL, "###lm_tcp_init is not supported for VF\n");
        return LM_STATUS_SUCCESS;
    }
    
    toe_info = &pdev->toe_info;
    mm_memset(toe_info, 0 , sizeof(lm_toe_info_t));
    toe_info->pdev = pdev;

    /* allocate resources */
    lm_status = lm_tcp_alloc_resc(pdev);
    DbgBreakIf((lm_status!=LM_STATUS_SUCCESS) && DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    /* initialize resources */
    lm_status = lm_tcp_init_resc(pdev, TRUE);
    DbgBreakIf(lm_status!=LM_STATUS_SUCCESS);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    /* initialize chip resources */
    lm_status = lm_tcp_init_chip(pdev);
    DbgBreakIf(lm_status!=LM_STATUS_SUCCESS);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    /* activate chip for tcp */
    lm_status = lm_tcp_start_chip(pdev);
    DbgBreakIf(lm_status!=LM_STATUS_SUCCESS);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    return lm_status;
}

/* Desciption:
 *  handle TOE init protocol ramrod completion */
void lm_tcp_init_ramrod_comp(lm_device_t *pdev)
{
    lm_toe_info_t *toe_info;

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_init_ramrod_comp\n");
    DbgBreakIf(!pdev);

    toe_info = &pdev->toe_info;
    DbgBreakIf(toe_info->state != LM_TOE_STATE_INIT);
    toe_info->state = LM_TOE_STATE_NORMAL;
}

/* Desciption:
 *  handle TOE RSS-update ramrod completion
 * Assumptions:
 * - called once for each RCQ
 */
void lm_tcp_rss_update_ramrod_comp(
    struct _lm_device_t *pdev,
    lm_tcp_rcq_t *rcq,
    u32_t cid,
    u32_t update_stats_type,
    u8_t update_suspend_rcq)
{

   /* decrement the completion count and check if we need to suspend processing */
   DbgBreakIf(rcq->suspend_processing == TRUE);

   /* Update update statistics - These statistics indicate which FW flow was taken and also count the overall number of updates */
    DbgMessage(pdev, INFORMl4sp, "lm_tcp_rss_update_ramrod_comp(): %d\n",update_stats_type);
    switch (update_stats_type) {
    case TOE_RSS_UPD_QUIET:
        rcq->rss_update_stats_quiet++;
        break;
    case TOE_RSS_UPD_SLEEPING:
        rcq->rss_update_stats_sleeping++;
        break;
    case TOE_RSS_UPD_DELAYED:
        rcq->rss_update_stats_delayed++;
        break;
    default:
        DbgBreak();
        break;
    }

    /* This is a hack due to the fact the FW has a hard time providing the cid on which the ramrod was sent on */
    /* I know that I sent the ramrod on the leading connection so I use it here instead of the cid on the cqe (update cid) */
    /* If the driver ever changes the cid on which the rmarod is snt on this line will have to be changed as well - UGLY, UGLY */
    rcq->update_cid = LM_SW_LEADING_RSS_CID(pdev);

    /* This is what should have been if the FW alwys put the ramrod cid on these completions
    rcq->update_cid = cid;
    */
    if (update_suspend_rcq) {
        lm_tcp_rss_update_suspend_rcq(pdev, rcq);
    } else {
        rcq->rss_update_processing_delayed++;
    }
}

/* Desciption:
 *  Checks whether the rcq processing should be suspended as a result of an rss update
 */
void lm_tcp_rss_update_suspend_rcq(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_rcq_t        * rcq)
{
    void * cookie = NULL;
    /*  This function is called once when an update completion is encountered and the rcq porcessing is not suspended yet.
     *  At all other times it is called only if the rcq processing is already suspended. */
    if (rcq->suspend_processing == FALSE)
    {
        /* decrment the expected completion counter */
        mm_atomic_dec(&pdev->params.update_comp_cnt);
        /* Toe specific... to determine who completes the ramrod. */
        if (mm_atomic_dec(&pdev->params.update_toe_comp_cnt) == 0)
        {
            /* Everyone is done. Time to return credit to the slowpath ring... */
            lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_RSS_UPDATE,
                           TOE_CONNECTION_TYPE, LM_TOE_FW_RSS_ID(pdev, LM_TOE_BASE_RSS_ID(pdev)));
        }
    }
    rcq->suspend_processing = pdev->params.update_toe_comp_cnt ? TRUE : FALSE;

    if (rcq->suspend_processing == FALSE)
    {
        /* processing was suspended and can now be resumed, try to complete the update ramrod */
        DbgMessage(pdev, INFORMl4sp, "lm_tcp_rss_update_suspend_rcq(): calling lm_eth_update_ramrod_comp\n");
        if (mm_atomic_dec(&pdev->params.update_suspend_cnt) == 0)
        {
            if (pdev->slowpath_info.set_rss_cookie)
            {
                cookie = (void *)pdev->slowpath_info.set_rss_cookie;
                pdev->slowpath_info.set_rss_cookie = NULL;
                mm_set_done(pdev, rcq->update_cid, cookie);
            }
        }
    }
}



/* Desciption:
 *  initiate a caller allocated lm neighbor state
 * Assumptions:
 *  - caller already zeroed given neigh state
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_tcp_init_neigh_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_neigh_state_t *neigh,
    l4_neigh_const_state_t *neigh_const,
    l4_neigh_cached_state_t *neigh_cached,
    l4_neigh_delegated_state_t *neigh_delegated)
{
    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init_neigh_state\n");
    DbgBreakIf(!(pdev && state_blk && neigh && neigh_const && neigh_cached && neigh_delegated));

    neigh->hdr.state_blk    = state_blk;
    neigh->hdr.state_id     = STATE_ID_NEIGH;
    neigh->hdr.status       = STATE_STATUS_NORMAL;
    d_list_push_tail(&state_blk->neigh_list, &neigh->hdr.link);
    neigh->num_dependents   = 0;

    mm_memcpy(&neigh->neigh_cached, neigh_cached, sizeof(neigh->neigh_cached));
    mm_memcpy(&neigh->neigh_const, neigh_const, sizeof(neigh->neigh_const));
    mm_memcpy(&neigh->neigh_delegated, neigh_delegated, sizeof(neigh->neigh_delegated));

    neigh->host_reachability_time   = 0; /* SHOULD BE: (mm_get_current_time() - neigh_cached->host_reachability_delta)   */
    neigh->nic_reachability_time    = 0; /* SHOULD BE: (mm_get_current_time() - neigh_delegated->nic_reachability_delta) */
    neigh->stale                    = 0;

    return LM_STATUS_SUCCESS;
}

/* Desciption:
 *  initiate a caller allocated lm path state
 * Assumptions:
 *  - caller already zeroed given path state
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_tcp_init_path_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_path_state_t *path,
    lm_neigh_state_t *neigh,
    l4_path_const_state_t *path_const,
    l4_path_cached_state_t *path_cached,
    l4_path_delegated_state_t *path_delegated)
{
    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init_path_state\n");
    DbgBreakIf(!(pdev && state_blk && path && neigh && path_const && path_cached && path_delegated));
    DbgBreakIf(neigh->hdr.state_id != STATE_ID_NEIGH || neigh->hdr.status != STATE_STATUS_NORMAL);

    path->hdr.state_blk     = state_blk;
    path->hdr.state_id      = STATE_ID_PATH;
    path->hdr.status        = STATE_STATUS_NORMAL;
    d_list_push_tail(&state_blk->path_list, &path->hdr.link);
    path->neigh             = neigh;
    neigh->num_dependents++;
    path->num_dependents    = 0;

    mm_memcpy(&path->path_cached, path_cached, sizeof(path->path_cached));
    mm_memcpy(&path->path_const, path_const, sizeof(path->path_const));
    mm_memcpy(&path->path_delegated, path_delegated, sizeof(path->path_delegated));

   return LM_STATUS_SUCCESS;
}

/* Desciption:
 *  initiate a caller allocated lm tcp state
 * Assumptions:
 *  - caller already zeroed given tcp state
 *  - caller already set the tx/rx_con pointers of the given
 *    tcp state to pre-allocated tx/rx cons
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_tcp_init_tcp_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_tcp_state_t *tcp,
    lm_path_state_t *path,
    l4_tcp_const_state_t *tcp_const,
    l4_tcp_cached_state_t *tcp_cached,
    l4_tcp_delegated_state_t *tcp_delegated,
    u32_t tcp_cid_addr)
{
    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init_tcp_state, ptr=%p, src_port=%d\n", tcp, tcp_const->src_port);
    DbgBreakIf(!(pdev && state_blk && tcp && path && tcp_const && tcp_cached && tcp_delegated));
    DbgBreakIf(path->hdr.state_id != STATE_ID_PATH || path->hdr.status != STATE_STATUS_NORMAL);

    /* We need to determine the ULP_TYPE and get ourselves a cid if one doesn't already exist */
    if (!tcp_cid_addr)
    {
        tcp->ulp_type = TOE_CONNECTION_TYPE;
    }
    else
    {
        tcp->ulp_type = lm_map_cid_to_proto(pdev, tcp_cid_addr);
        tcp->cid = tcp_cid_addr;
        lm_set_cid_resc(pdev, TOE_CONNECTION_TYPE, tcp, tcp_cid_addr);
    }

    tcp->hdr.state_blk     = state_blk;
    tcp->hdr.state_id      = STATE_ID_TCP;
    tcp->hdr.status        = STATE_STATUS_INIT;
    d_list_push_tail(&state_blk->tcp_list, &tcp->hdr.link);
    tcp->path = path;
    path->num_dependents++;

    if (tcp->ulp_type == TOE_CONNECTION_TYPE)
    {
        pdev->toe_info.stats.total_ofld++;
    }
    else if (tcp->ulp_type == ISCSI_CONNECTION_TYPE)
    {
        pdev->iscsi_info.run_time.stats.total_ofld++;
    }

    mm_memcpy(&tcp->tcp_cached, tcp_cached, sizeof(tcp->tcp_cached));
    mm_memcpy(&tcp->tcp_const, tcp_const, sizeof(tcp->tcp_const));
    mm_memcpy(&tcp->tcp_delegated, tcp_delegated, sizeof(tcp->tcp_delegated));

    /* the rest of the tcp state's fields that require initialization value other than 0,
     * will be initialized later (when lm_tcp_init_tx_con/lm_tcp_init_rx_con/lm_tcp_init_tcp_context are called) */

    return LM_STATUS_SUCCESS;
}

/* calc connection's mss according to path_mtu and remote MSS */
static u32_t _lm_tcp_calc_mss(u32_t path_mtu, u16_t remote_mss, u8_t is_ipv6, u8_t ts_enabled,
                              u8_t llc_snap_enabled, u8_t vlan_enabled)
{
#define MIN_MTU         576 /* rfc 793 */
#define IPV4_HDR_LEN    20
#define IPV6_HDR_LEN    40
#define TCP_HDR_LEN     20
#define TCP_OPTION_LEN  12
#define LLC_SNAP_LEN     8
#define VLAN_LEN         4

    u32_t mss  = 0;
    u32_t hdrs = TCP_HDR_LEN;

    UNREFERENCED_PARAMETER_(vlan_enabled);
    UNREFERENCED_PARAMETER_(llc_snap_enabled);

    if(is_ipv6) {
        hdrs += IPV6_HDR_LEN;
    } else {
        hdrs += IPV4_HDR_LEN;
    }
#ifdef LLC_SNAP_HEADER_ROOMS_WITH_PAYLOAD
/*
    LLC_SNAP_HEADER_ROOMS_WITH_PAYLOAD never was defined. Nobody remembers when LLC/SNAP protocol was tested but
    in any case don't use payload to room LLC/SNAP header
*/
    if (llc_snap_enabled) {
        hdrs += LLC_SNAP_LEN;
    }
#endif
#ifdef VLAN_HEADER_ROOMS_WITH_PAYLOAD
/*
    VLAN_HEADER_ROOMS_WITH_PAYLOAD never was defined and below strings is reminder that once there was problem of
    decreasing (-4) data payload size because of VLAN header rooming with payload CQ39709
*/
    if (vlan_enabled) {
        hdrs += VLAN_LEN;
    }
#endif
    DbgBreakIf(path_mtu < MIN_MTU);
    mss = path_mtu - hdrs;

    if(mss > remote_mss) {
        mss = remote_mss;
    }
    if(ts_enabled) {
        mss -= TCP_OPTION_LEN;
    }
    if (!mss) {
        DbgBreakIf(!mss);
        mss = 1; /*mss may be used as divider, so let's prevent division by zero*/
    }
    return mss;
}

/** Description
 *  calculate the fragment count for a given initial receive window and mss
 *  The fragment count is based on the maximum size we will need to do for a single
 *  indication
 */
static u32_t _lm_tcp_calc_frag_cnt(lm_device_t * pdev, u32_t initial_rcv_wnd, u32_t mss)
{
    u32_t frag_cnt;

    frag_cnt = initial_rcv_wnd / mss;
    if (frag_cnt < (0x10000 / mss)) {
        frag_cnt = 0x10000 / mss;
    }

    if ((pdev->params.l4_max_rcv_wnd_size > 0x10000) && (frag_cnt > (pdev->params.l4_max_rcv_wnd_size / mss))) {
        frag_cnt = pdev->params.l4_max_rcv_wnd_size / mss;
    }
    frag_cnt = frag_cnt * 2 + 1;

    if (pdev->params.l4_max_gen_buf_cnt && (frag_cnt > pdev->params.l4_max_gen_buf_cnt)) {
        frag_cnt = pdev->params.l4_max_gen_buf_cnt;
    }
    return frag_cnt;
}

u32_t lm_tcp_calc_frag_cnt(
        lm_device_t * pdev,
        lm_tcp_state_t * tcp
    )
{
    u32_t mss, frag_cnt;
    DbgBreakIf(!(pdev && tcp));
    mss = _lm_tcp_calc_mss(tcp->path->path_cached.path_mtu,
                           tcp->tcp_const.remote_mss,
                           (tcp->path->path_const.ip_version == IP_VERSION_IPV6),
                           tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP,
                           FALSE,
                           tcp->path->neigh->neigh_const.vlan_tag != 0);

    frag_cnt = _lm_tcp_calc_frag_cnt(pdev, tcp->tcp_cached.initial_rcv_wnd, mss);

    return frag_cnt;
}



static void _lm_tcp_init_qe_buffer(
    struct _lm_device_t * pdev,
    lm_tcp_qe_buffer_t  * qe_buffer,
    u8_t                * mem_virt,
    u32_t                 cnt,
    u8_t                  cqe_size)
{
    UNREFERENCED_PARAMETER_(pdev);

    qe_buffer->left    = cnt;
    qe_buffer->first   = (char *)mem_virt;
    qe_buffer->head    = qe_buffer->first;
    qe_buffer->tail    = qe_buffer->first;
    qe_buffer->last    = qe_buffer->first;
    qe_buffer->last   += (qe_buffer->left-1)*cqe_size;
    qe_buffer->qe_size = cqe_size;
}

/** Description
 *  function calculates the amount of virtual memory required for the RX connection
 * Return
 *  amount of virtual memory required
 */
u32_t lm_tcp_rx_con_get_virt_size(struct _lm_device_t * pdev, lm_tcp_state_t * tcp)
{
    u32_t frag_cnt;
    u32_t mem_size;
    u32_t mss;

    /* The calculation for frag_cnt is based on the calculation from Teton's init_rx_tcp_resc()
     * also the assertion is taken from Teton */
    DbgBreakIf(tcp->tcp_cached.initial_rcv_wnd == 0);
    /* the rx_con may not be initialized at this state, therefore we can't rely on the mss being initialized. */
    mss = _lm_tcp_calc_mss(tcp->path->path_cached.path_mtu,
                           tcp->tcp_const.remote_mss,
                           (tcp->path->path_const.ip_version == IP_VERSION_IPV6),
                           tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP,
                           pdev->ofld_info.l4_params.flags & OFLD_PARAM_FLAG_SNAP_ENCAP,
                           tcp->path->neigh->neigh_const.vlan_tag  != 0);

    frag_cnt = _lm_tcp_calc_frag_cnt(pdev, tcp->tcp_cached.initial_rcv_wnd, mss);


    DbgMessage(pdev, INFORMl4rx, "Calc #frags for rx-con initial_rcv_wnd: %d frag_cnt: %d\n", tcp->tcp_cached.initial_rcv_wnd, frag_cnt);

    mem_size = sizeof(lm_frag_list_t) + (frag_cnt - 1)*sizeof(lm_frag_t);

    return mem_size;
}

void lm_tcp_init_tcp_sp_data_mem(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp
    )
{
    /* slow-path physical memory */
    /* allocation of physical area for sp request */
    lm_sp_req_manager_t *sp_req_mgr = NULL;

    sp_req_mgr = lm_cid_sp_req_mgr(pdev, tcp->cid);
    if CHK_NULL(sp_req_mgr)
    {
        DbgBreakIf(!sp_req_mgr);
        return;
    }
    DbgBreakIf(sp_req_mgr->sp_data_phys_addr.as_u32.low & CACHE_LINE_SIZE_MASK);
    tcp->sp_req_data.phys_addr = sp_req_mgr->sp_data_phys_addr;
    tcp->sp_req_data.virt_addr = sp_req_mgr->sp_data_virt_addr;
}


void lm_tcp_init_tcp_phys_mem(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_phy_mem_block_t * phy_mblk)
{
    lm_tcp_con_t * con;
    u32_t mem_size;
    u16_t page_cnt,page_idx;
    u32_t idx = 0;
    u8_t  bd_size;
    u8_t  block_idx;

    #if (LM_PAGE_SIZE != 4096)
    #error (LM_PAGE_SIZE != 4096) /* currently FW assumes a tx chain page is 4KB */
    #endif

    /* Init physical memory */
    /* bd-chains */
    con = tcp->tx_con;
    page_cnt = (u16_t)pdev->params.l4_tx_chain_page_cnt;
    bd_size = sizeof(struct toe_tx_bd);
    block_idx = 0;
    for (idx = 0 ; idx < 2; idx++) {
        mem_size = LM_PAGE_SIZE;
        for (page_idx = 0; page_idx < page_cnt; page_idx++) {
            if (phy_mblk[block_idx].left < mem_size) {
                block_idx++;
                DbgBreakIf(block_idx == pdev->params.l4_num_of_blocks_per_connection);
            }
            DbgBreakIf(phy_mblk[block_idx].left < mem_size);
            lm_bd_chain_add_page(pdev,&con->bd_chain,phy_mblk[block_idx].free, phy_mblk[block_idx].free_phy, bd_size, TRUE);
            phy_mblk[block_idx].free += mem_size;
            phy_mblk[block_idx].left -= mem_size;
            LM_INC64(&phy_mblk[block_idx].free_phy, mem_size);
        }
        /* rx-con */
        con = tcp->rx_con;
        page_cnt = (u16_t)pdev->params.l4_rx_chain_page_cnt;
        bd_size = sizeof(struct toe_rx_bd);
    }

    /* slow-path physical memory */
    /* allocation of physical area for sp request */
    mem_size = TOE_SP_PHYS_DATA_SIZE;

    if (phy_mblk[block_idx].left < mem_size) {
        block_idx++;
        DbgBreakIf(block_idx == pdev->params.l4_num_of_blocks_per_connection);
    }
    DbgBreakIf(mem_size > phy_mblk[block_idx].left);
    DbgBreakIf(phy_mblk[block_idx].free_phy.as_u32.low & CACHE_LINE_SIZE_MASK);
    tcp->sp_req_data.phys_addr = phy_mblk[block_idx].free_phy;
    tcp->sp_req_data.virt_addr = (lm_tcp_slow_path_phys_data_t *)phy_mblk[block_idx].free;
    mm_memset(tcp->sp_req_data.virt_addr, 0, mem_size);
    phy_mblk[block_idx].free += mem_size;
    phy_mblk[block_idx].left -= mem_size;
    LM_INC64(&phy_mblk[block_idx].free_phy, mem_size);

    /* doorbell data */
    /* init tx part */
    mem_size = TOE_DB_TX_DATA_SIZE;
    if (phy_mblk[block_idx].left < mem_size) {
        block_idx++;
        DbgBreakIf(block_idx == pdev->params.l4_num_of_blocks_per_connection);
    }
    DbgBreakIf(mem_size > phy_mblk[block_idx].left);
    DbgBreakIf(phy_mblk[block_idx].free_phy.as_u32.low & CACHE_LINE_SIZE_MASK);
    tcp->tx_con->phys_db_data = phy_mblk[block_idx].free_phy;
    tcp->tx_con->db_data.tx = (volatile struct toe_tx_db_data *)phy_mblk[block_idx].free;
    tcp->tx_con->db_data.tx->flags = 0;
    tcp->tx_con->db_data.tx->bds_prod = 0;
    /* init tx db data to snd.una (+ sizeof sent unacked data that will
     * be initiated when sent unacked data is posted): */
    tcp->tx_con->db_data.tx->bytes_prod_seq = tcp->tcp_delegated.send_una;
    phy_mblk[block_idx].free += mem_size;
    phy_mblk[block_idx].left -= mem_size;
    LM_INC64(&phy_mblk[block_idx].free_phy, mem_size);


    /* init rx part */
    if (phy_mblk[block_idx].left < mem_size) {
        block_idx++;
        DbgBreakIf(block_idx == pdev->params.l4_num_of_blocks_per_connection);
    }
    mem_size = TOE_DB_RX_DATA_SIZE;
    DbgBreakIf(mem_size > phy_mblk[block_idx].left);
    DbgBreakIf(phy_mblk[block_idx].free_phy.as_u32.low & CACHE_LINE_SIZE_MASK);
    tcp->rx_con->phys_db_data = phy_mblk[block_idx].free_phy;
    tcp->rx_con->db_data.rx = (volatile struct toe_rx_db_data *)phy_mblk[block_idx].free;
    phy_mblk[block_idx].free += mem_size;
    phy_mblk[block_idx].left -= mem_size;
    LM_INC64(&phy_mblk[block_idx].free_phy, mem_size);
    tcp->rx_con->db_data.rx->rcv_win_right_edge = tcp->tcp_delegated.recv_win_seq;
    /* we also need to initialize the driver copy of the rcv_win_right_edge */
    tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge = tcp->tcp_delegated.recv_win_seq;
    tcp->rx_con->db_data.rx->bds_prod = 0;
    tcp->rx_con->db_data.rx->bytes_prod = 0;
    tcp->rx_con->db_data.rx->consumed_grq_bytes = 0;
    tcp->rx_con->db_data.rx->flags = 0;
    tcp->rx_con->db_data.rx->reserved1 = 0;
}

void lm_tcp_init_tcp_virt_mem(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_mem_block_t * mblk)
{
    lm_tcp_con_t * con;
    u32_t mem_size;

    u32_t idx = 0;
    u8_t  cqe_size;

    con = tcp->tx_con;
    cqe_size = sizeof(struct toe_tx_cqe);
    for (idx = 0; idx < 2; idx++) {
        /* allocation of buffers for history CQEs */
        if (pdev->params.l4_history_cqe_cnt) {
            mem_size = pdev->params.l4_history_cqe_cnt*cqe_size;
            DbgBreakIf(mblk->left < mem_size);
            _lm_tcp_init_qe_buffer(pdev, &con->history_cqes, mblk->free, pdev->params.l4_history_cqe_cnt, cqe_size);
            mblk->free += mem_size;
            mblk->left -= mem_size;
        } else {
            DbgBreakMsg("MichalS: Currently History Count = 0 is not SUPPORTED\n");
        }
        con = tcp->rx_con;
        cqe_size = sizeof(struct toe_rx_cqe);
    }

    /* rx frag list */
    mem_size = lm_tcp_rx_con_get_virt_size(pdev, tcp);
    DbgBreakIf(mblk->left < mem_size);

    tcp->rx_con->u.rx.gen_info.frag_list = (lm_frag_list_t *)mblk->free;
    mblk->free += mem_size;
    mblk->left -= mem_size;

}
lm_status_t lm_tcp_init_tcp_resc(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_mem_block_t * mblk,
    lm_tcp_phy_mem_block_t * phy_mblk)
{
    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init_tx_con\n");
    DbgBreakIf(!(pdev && tcp));

    /* tx-specific */
    tcp->tx_con->type = TCP_CON_TYPE_TX;
    mm_memset(&tcp->tx_con->u.tx, 0, sizeof(lm_tcp_con_tx_t));

    tcp->tx_con->flags = (TCP_POST_BLOCKED | TCP_COMP_BLOCKED);
    tcp->tx_con->tcp_state = tcp;
    s_list_init(&tcp->tx_con->active_tb_list, NULL, NULL, 0);

    /* rx-specific */
    tcp->rx_con->type = TCP_CON_TYPE_RX;
    mm_memset(&tcp->rx_con->u.rx, 0, sizeof(lm_tcp_con_rx_t));

    tcp->rx_con->flags = (TCP_POST_BLOCKED | TCP_COMP_BLOCKED);
    tcp->rx_con->tcp_state = tcp;
    s_list_init(&tcp->rx_con->active_tb_list, NULL, NULL, 0);

    lm_tcp_init_tcp_phys_mem(pdev,tcp,phy_mblk);

    lm_tcp_init_tcp_virt_mem(pdev,tcp,mblk);


    tcp->rx_con->u.rx.sws_info.mss = tcp->tx_con->u.tx.mss =
        _lm_tcp_calc_mss(tcp->path->path_cached.path_mtu,
                         tcp->tcp_const.remote_mss,
                         (tcp->path->path_const.ip_version == IP_VERSION_IPV6),
                         tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP,
                         pdev->ofld_info.l4_params.flags & OFLD_PARAM_FLAG_SNAP_ENCAP,
                         tcp->path->neigh->neigh_const.vlan_tag  != 0);



    tcp->rx_con->u.rx.gen_info.max_frag_count  = _lm_tcp_calc_frag_cnt(pdev, tcp->tcp_cached.initial_rcv_wnd, tcp->rx_con->u.rx.sws_info.mss);
    return LM_STATUS_SUCCESS;
}

/* Function returns the required size for a virtual connection. If tcp_state is given,
 * the size is calculated for the specific connection given, o/w the default size is given.
 */
u32_t lm_tcp_get_virt_size(
    struct _lm_device_t * pdev,
    lm_tcp_state_t * tcp_state)
{
    u32_t       virt_size = 0;
    u32_t       mss       = 0;
    u32_t const chain_idx = LM_SW_LEADING_RSS_CID(pdev);

    virt_size =
        pdev->params.l4_history_cqe_cnt*sizeof(struct toe_tx_cqe)   +
        pdev->params.l4_history_cqe_cnt*sizeof(struct toe_rx_cqe);

    if (tcp_state)
    {
        virt_size += lm_tcp_rx_con_get_virt_size(pdev,tcp_state);
    }
    else
    {
        #define LM_TCP_DEFAULT_WINDOW_SIZE 0x10000

        if(CHK_NULL(pdev) ||
        ERR_IF((ARRSIZE(pdev->params.l2_cli_con_params) <= chain_idx) ||
                (CHIP_IS_E1H(pdev) && (chain_idx >= ETH_MAX_RX_CLIENTS_E1H)) || /* TODO E2 add IS_E2*/
                (CHIP_IS_E1(pdev) && (chain_idx >= ETH_MAX_RX_CLIENTS_E1)) ))
        {
            DbgBreakIf(1);
            return 0;
        }

        mss = _lm_tcp_calc_mss(pdev->params.l2_cli_con_params[chain_idx].mtu, 0xffff, FALSE, FALSE, FALSE, FALSE);
        virt_size += sizeof(lm_frag_list_t) +
            (_lm_tcp_calc_frag_cnt(pdev, LM_TCP_DEFAULT_WINDOW_SIZE, mss) - 1)*sizeof(lm_frag_t);
    }
    return virt_size;
}

u32_t lm_tcp_get_phys_size(
    struct _lm_device_t * pdev)
{
    u32_t mem_size = TOE_SP_PHYS_DATA_SIZE + TOE_DB_TX_DATA_SIZE + TOE_DB_RX_DATA_SIZE;

    mem_size = ((mem_size / LM_PAGE_SIZE) + 1) * LM_PAGE_SIZE;

    mem_size += pdev->params.l4_rx_chain_page_cnt*LM_PAGE_SIZE + /* rx bd-chain */
            pdev->params.l4_tx_chain_page_cnt*LM_PAGE_SIZE; /* tx bd-chain */

    return mem_size;
}

lm_status_t lm_tcp_post_buffered_data(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    d_list_t *buffered_data)
{
    lm_tcp_con_rx_gen_info_t * gen_info     = NULL;
    lm_tcp_gen_buf_t         * curr_gen_buf = NULL;

    DbgBreakIf(!buffered_data);
    if(!d_list_is_empty(buffered_data)) {
        gen_info = &tcp->rx_con->u.rx.gen_info;
        curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_head(buffered_data);
        DbgBreakIf(!d_list_is_empty(&gen_info->peninsula_list));
        d_list_add_head(&gen_info->peninsula_list, buffered_data);
        /* initialize peninsula_nbytes */
        while (curr_gen_buf) {
            gen_info->peninsula_nbytes += curr_gen_buf->placed_bytes;
            curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_next_entry(&curr_gen_buf->link);
        }

        DbgBreakIf(tcp->rx_con->flags & TCP_INDICATE_REJECTED);
        tcp->rx_con->flags |= TCP_RX_COMP_DEFERRED; /* TCP_INDICATE_REJECTED was here to wait rx buffers from OS.
                                                       With TCP_RX_COMP_DEFERRED flag processing of completion
                                                       SP_REQUEST_INITIATE_OFFLOAD will indicate the buffered data
                                                       if it needed */
    }


    return LM_STATUS_SUCCESS;
}

/* calculate tcp pseudo check sum.
 * input and retured value in _network_ order */
static u16_t lm_tcp_calc_tcp_pseudo_checksum(
    struct _lm_device_t *pdev,
    u32_t n_src_ip[4],
    u32_t n_dst_ip[4],
    u8_t ip_type)
{
#define D_IP_PROTOCOL_TCP 6
    u32_t sum = 0;
    int i;

    if(ip_type == IP_VERSION_IPV4) { /* IPV4 */
        sum += n_src_ip[0] & 0xffff;
        sum += (n_src_ip[0]>>16) & 0xffff;

        sum += n_dst_ip[0] & 0xffff;
        sum += (n_dst_ip[0]>>16) & 0xffff;
    } else {
        for (i = 0; i < 4; i++) {
            sum += n_src_ip[i] & 0xffff;
            sum += (n_src_ip[i]>>16) & 0xffff;
        }
        for (i = 0; i < 4; i++) {
            sum += n_dst_ip[i] & 0xffff;
            sum += (n_dst_ip[i]>>16) & 0xffff;
        }
    }

    sum +=  HTON16((u16_t)(D_IP_PROTOCOL_TCP));

   /* Fold 32-bit sum to 16 bits */
   while( sum >> 16 ) {
       sum = (sum & 0xffff) + (sum >> 16);
   }

   DbgMessage(pdev, VERBOSEl4sp,
               "_lm_tcp_calc_tcp_pseudo_checksum: n_src_ip=%x, n_dst_ip=%x, (u16_t)sum=%x\n",
               n_src_ip[0], n_dst_ip[0], (u16_t)sum);

   return (u16_t)sum;
}

/* find the bd in the bd chain that contains snd_nxt, the offset of snd_nxt
 * within this bd, and the base address of the page that contains this bd. */
static lm_status_t lm_locate_snd_next_info(
    lm_tcp_con_t * tx_con,
    u32_t          snd_nxt,
    u32_t          snd_una,
    u16_t        * bd_idx,
    u16_t        * bd_offset,
    lm_address_t * page_addr)
{
    u32_t              cur_seq   = 0;
    struct toe_tx_bd * cur_tx_bd = NULL;

    /* we assume that the first byte of the first application buffer equals SND.UNA
     * we need to find SND.NXT relative to this */
    DbgMessage(NULL, VERBOSEl4sp, "### lm_locate_snd_next_info\n");

    /* want to make sure the consumer is still zero ... */
    if ((tx_con->bd_chain.cons_idx != 0) ||
        (S32_SUB(tx_con->bytes_post_cnt ,S32_SUB(snd_nxt, snd_una)) < 0) ||
        (tx_con->bytes_comp_cnt))
    {
        DbgBreakIf(tx_con->bd_chain.cons_idx != 0);
        DbgBreakIf(S32_SUB(tx_con->bytes_post_cnt ,S32_SUB(snd_nxt, snd_una)) < 0);
        DbgBreakIf(tx_con->bytes_comp_cnt); /* nothing should be completed yet */
        return LM_STATUS_INVALID_PARAMETER;
    }

    *bd_idx = 0;
    *bd_offset = 0;
    *page_addr = tx_con->bd_chain.bd_chain_phy;

    if (lm_bd_chain_prod_idx(&tx_con->bd_chain) == 0) {
        /* If the producer is '0', chain is empty. bd_idx/offset are 0 */
        if ((tx_con->bytes_post_cnt > 0) ||
            (snd_nxt != snd_una))
        {
            DbgBreakIf(tx_con->bytes_post_cnt > 0);
            /* Notice: This case was seen and its a bug in the MS stack: delegated: snd_nxt > snd_una but WITHOUT unacked data */
            DbgBreakIf(snd_nxt != snd_una);
            return LM_STATUS_INVALID_PARAMETER;
        }
        return LM_STATUS_SUCCESS;
    }

    cur_seq    = snd_una;
    cur_tx_bd  = (struct toe_tx_bd *)tx_con->bd_chain.bd_chain_virt;

    while ((*bd_idx < lm_bd_chain_prod_idx(&tx_con->bd_chain))
        && S32_SUB(snd_nxt, cur_seq + cur_tx_bd->size) >= 0) {
        /* Advance to the next bd. */
        cur_seq += cur_tx_bd->size;
        lm_bd_chain_incr_bd(&tx_con->bd_chain, page_addr, (void**)&cur_tx_bd, bd_idx);
    }

    /* make sure assignment is legit. */
    if ((S32_SUB(snd_nxt, cur_seq) < 0) ||
        (S32_SUB(snd_nxt, cur_seq) > 0xffff))
    {
        DbgBreakIf(S32_SUB(snd_nxt, cur_seq) < 0 );
        DbgBreakIf(S32_SUB(snd_nxt, cur_seq) > 0xffff );
        return LM_STATUS_INVALID_PARAMETER;
    }

    *bd_offset = S32_SUB(snd_nxt, cur_seq);
    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_init_xstorm_toe_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t * tcp)
{
    struct toe_context * ctx                = (struct toe_context *)tcp->ctx_virt;
    struct xstorm_toe_ag_context * xctx_ag  = &ctx->xstorm_ag_context;
    struct xstorm_toe_st_context * xctx_st  = &ctx->xstorm_st_context.context;
    lm_address_t                  mem_phys  = {{0}};
    u16_t                         bd_idx    = 0;
    u16_t                         bd_offset = 0;
    lm_status_t                   lm_status = LM_STATUS_SUCCESS;

    /* xstorm ag context */
    mm_memset(xctx_ag, 0, sizeof(struct xstorm_toe_ag_context));

    if(tcp->tcp_cached.tcp_flags & TCP_FLAG_ENABLE_NAGLING)
    {
        xctx_ag->agg_vars1 |= XSTORM_TOE_AG_CONTEXT_NAGLE_EN;
    }
    /* Initialize Send-Una info */
    mem_phys = lm_bd_chain_phys_addr(&tcp->tx_con->bd_chain, 0);
    xctx_ag->cmp_bd_cons           = 0;                           /* idx of bd with snd.una - always 0 */
    xctx_ag->cmp_bd_page_0_to_31   = mem_phys.as_u32.low;         /* page that includes the snd.una */
    xctx_ag->cmp_bd_page_32_to_63  = mem_phys.as_u32.high;        /* page that includes the snd.una */
    xctx_ag->cmp_bd_start_seq      = tcp->tcp_delegated.send_una; /* the sequence number of the first byte in the bd which holds SndUna */

    /* more_to_send: The difference between SndNxt and the last byte in the bd pointed by bd prod */
    if (tcp->tx_con->bytes_comp_cnt)
    {
        DbgBreakIf(tcp->tx_con->bytes_comp_cnt);
        return LM_STATUS_INVALID_PARAMETER;
    }
    xctx_ag->more_to_send = S32_SUB(tcp->tx_con->bytes_post_cnt,(S32_SUB(tcp->tcp_delegated.send_next,tcp->tcp_delegated.send_una)));
    if ((tcp->tx_con->flags & TCP_FIN_REQ_POSTED) && !(tcp->tx_con->flags & TCP_FIN_REQ_COMPLETED)) {
        xctx_ag->more_to_send--; /* the fin byte on the bd chain is not counted */
    }

    /* xstorm st context */
    mm_memset(xctx_st, 0, sizeof(struct xstorm_toe_st_context));
    lm_status = lm_locate_snd_next_info(tcp->tx_con, tcp->tcp_delegated.send_next, tcp->tcp_delegated.send_una,
                            &bd_idx, &bd_offset, &mem_phys);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    xctx_st->toe.tx_bd_cons                   = bd_idx;    /* index of bd that includes snd_nxt */
    xctx_st->toe.tx_bd_offset                 = bd_offset; /* offset of snd_nxt within its bd */
    xctx_st->toe.tx_bd_page_base_hi           = mem_phys.as_u32.high;
    xctx_st->toe.tx_bd_page_base_lo           = mem_phys.as_u32.low;

    xctx_st->toe.bd_prod                      = lm_bd_chain_prod_idx(&tcp->tx_con->bd_chain); /* Bd containing the last byte the application wishes to trasnmit */
    xctx_st->toe.driver_doorbell_info_ptr_lo  = tcp->tx_con->phys_db_data.as_u32.low;
    xctx_st->toe.driver_doorbell_info_ptr_hi  = tcp->tx_con->phys_db_data.as_u32.high;

    return LM_STATUS_SUCCESS;
}


static lm_status_t _lm_tcp_init_ustorm_toe_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    struct toe_context *          ctx      = (struct toe_context *)tcp->ctx_virt;
    struct ustorm_toe_ag_context *uctx_ag  = &ctx->ustorm_ag_context;
    struct ustorm_toe_st_context *uctx_st  = &ctx->ustorm_st_context.context;
    lm_address_t                  mem_phys = {{0}};

    /* Calculate the crc8 for CDU Validation */
    mm_memset(uctx_ag, 0, sizeof(struct ustorm_toe_ag_context));

    /* ustorm_ag_context */
    uctx_ag->rq_prod                     = 0;
    uctx_ag->driver_doorbell_info_ptr_hi = tcp->rx_con->phys_db_data.as_u32.high;
    uctx_ag->driver_doorbell_info_ptr_lo = tcp->rx_con->phys_db_data.as_u32.low;

    /* ustorm_st_context */
    mm_memset(uctx_st, 0, sizeof(struct ustorm_toe_st_context));
    uctx_st->indirection_ram_offset   = (u16_t)tcp->tcp_const.hash_value;
    uctx_st->pen_grq_placed_bytes     = tcp->rx_con->u.rx.gen_info.peninsula_nbytes;
    DbgMessage(pdev, INFORMl4sp, "_lm_tcp_init_ustorm_toe_context: IRO is 0x%x, IS is %d\n",
                uctx_st->indirection_ram_offset, uctx_st->__indirection_shift);
    if ((tcp->tcp_cached.rcv_indication_size > 0xffff) ||
        (tcp->tcp_cached.rcv_indication_size != 0))
    {
        DbgBreakIf(tcp->tcp_cached.rcv_indication_size > 0xffff);
        DbgBreakIf(tcp->tcp_cached.rcv_indication_size != 0); /* TBA receive_indication_size != 0 not supported : if it is we need to change initialization below */
        return LM_STATUS_INVALID_PARAMETER;
    }
    /* We set the ustorm context to rcv_indication_size = 1 byte, this means that the first packet that is placed on GRQ,
     * that exceeds or equals 1 byte is indicated immediately, without arming the push timer, the first packet is identified by
     * a packet that is placed while there are no GRQ placed bytes, every time that the driver advertises 'consumedGRQ', GRQ placed bytes
     * is decreased by the number, bringing it back to '0' will bring us back to the state where the next packet with 1 byte will be indicated.
     * We added this feature due to a sparta test called ReceiveIndication, which sends a fairly small packet and expects it to be indicated straight
     * awat, for some reason the small RQ buffer doesn't make it's way to the VBD... */
    uctx_st->rcv_indication_size      = 1;
    mem_phys = lm_bd_chain_phys_addr(&tcp->rx_con->bd_chain, 0);
    uctx_st->pen_ring_params.rq_cons  = 0;
    uctx_st->pen_ring_params.rq_cons_addr_hi = mem_phys.as_u32.high;
    uctx_st->pen_ring_params.rq_cons_addr_lo = mem_phys.as_u32.low;

    uctx_st->prev_rcv_win_right_edge = tcp->rx_con->db_data.rx->rcv_win_right_edge;

    if (pdev->params.l4_ignore_grq_push_enabled)
    {
        SET_FLAGS(uctx_st->flags2, USTORM_TOE_ST_CONTEXT_IGNORE_GRQ_PUSH);
    }

    if (pdev->params.l4_enable_rss == L4_RSS_DYNAMIC)
    {
        SET_FLAGS( uctx_st->flags2, USTORM_TOE_ST_CONTEXT_RSS_UPDATE_ENABLED );
    }
    /*DbgMessage(pdev, FATAL, "_lm_tcp_init_ustorm_toe_context(): uctx_st->initial_rcv_wnd=%d\n", tcp->tcp_cached.initial_rcv_wnd);*/
    uctx_st->initial_rcv_wnd = tcp->tcp_cached.initial_rcv_wnd;
    uctx_st->rcv_nxt         = tcp->tcp_delegated.recv_next;

    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_init_cstorm_toe_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    struct toe_context           *ctx      = (struct toe_context *)tcp->ctx_virt;
    struct cstorm_toe_ag_context *cctx_ag  = &ctx->cstorm_ag_context;
    struct cstorm_toe_st_context *cctx_st  = &ctx->cstorm_st_context.context;
    lm_address_t                  mem_phys = {{0}};

    mm_memset(cctx_ag, 0, sizeof(struct cstorm_toe_ag_context));

    if (tcp->tcp_cached.initial_rcv_wnd > MAX_INITIAL_RCV_WND)
    {
        /* we can't support more than the maximum receive window due to cyclic counters we use for
         * recv_next, recv_win_seq, updates, window increase */
        DbgBreakIfAll(tcp->tcp_cached.initial_rcv_wnd > MAX_INITIAL_RCV_WND);
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* cstorm_ag_context */
    cctx_ag->bd_prod = lm_bd_chain_prod_idx(&tcp->tx_con->bd_chain); /* Bd containing the last byte the application wishes to trasnmit */
    cctx_ag->rel_seq = tcp->tcp_delegated.send_una;
    cctx_ag->snd_max = tcp->tcp_delegated.send_max;

    /* cstorm_st_context */
    mm_memset(cctx_st, 0, sizeof(struct cstorm_toe_st_context));
    mem_phys = lm_bd_chain_phys_addr(&tcp->tx_con->bd_chain, 0);
    cctx_st->bds_ring_page_base_addr_hi = mem_phys.as_u32.high; /* page that includes the snd.una */
    cctx_st->bds_ring_page_base_addr_lo = mem_phys.as_u32.low;  /* page that includes the snd.una */
    cctx_st->bd_cons          = 0; /* idx of bd with snd.una - always 0 */
    if (ERR_IF(tcp->tcp_const.hash_value >= (u8_t)USTORM_INDIRECTION_TABLE_SIZE)) {
        if (tcp->tcp_const.hash_value >= (u8_t)USTORM_INDIRECTION_TABLE_SIZE)
        {
            DbgBreakIfAll(tcp->tcp_const.hash_value >= (u8_t)USTORM_INDIRECTION_TABLE_SIZE);
            return LM_STATUS_INVALID_PARAMETER;
        }
        tcp->tcp_const.hash_value = LM_TOE_FW_RSS_ID(pdev,LM_TOE_BASE_RSS_ID(pdev));
    }

    cctx_st->prev_snd_max = tcp->tcp_delegated.send_una;




    /* For TOE RSS the values in the USTORM (RSS) must differ from the one in CSTORM (TSS)
       2 options:
        a. base chain.
        b. value of most up-to-date indirection table.
    */
    if (pdev->params.l4_enable_rss == L4_RSS_DISABLED)
    {
        cctx_st->cpu_id = LM_TOE_FW_RSS_ID(pdev,LM_TOE_BASE_RSS_ID(pdev));
    }
    else
    {
        cctx_st->cpu_id = pdev->toe_info.indirection_table[tcp->tcp_const.hash_value];
    }

    cctx_st->free_seq = tcp->tcp_delegated.send_una - 1; /* (snd.una - 1 - offset of snd.una byte in its buffer (which is always 0)) */

    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_init_tstorm_toe_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t * tcp)
{
    struct toe_context * ctx = (struct toe_context *)tcp->ctx_virt;
    struct tstorm_toe_ag_context * tctx_ag = &ctx->tstorm_ag_context;
    struct tstorm_toe_st_context * tctx_st = &ctx->tstorm_st_context.context;

    UNREFERENCED_PARAMETER_(pdev);

    /* tstorm ag context */
    mm_mem_zero(tctx_ag, sizeof(struct tstorm_toe_ag_context));

    /* tstorm st context */
    mm_mem_zero(tctx_st, sizeof(struct tstorm_toe_st_context));

    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_init_timers_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    struct toe_context * ctx = (struct toe_context *)tcp->ctx_virt;
    /* timers_context */
    SET_FLAGS(ctx->timers_context.flags, TIMERS_BLOCK_CONTEXT_CONN_VALID_FLG);

    UNREFERENCED_PARAMETER_(pdev);

    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_init_toe_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    lm_status = _lm_tcp_init_xstorm_toe_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }
    lm_status = _lm_tcp_init_ustorm_toe_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }
    lm_status = _lm_tcp_init_cstorm_toe_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }
    lm_status = _lm_tcp_init_tstorm_toe_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }
    lm_status = _lm_tcp_init_timers_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    /* now we need to configure the cdu-validation data */
    lm_set_cdu_validation_data(pdev, tcp->cid, FALSE /* don't invalidate */);
    return LM_STATUS_SUCCESS;
}


static lm_status_t _lm_tcp_init_tstorm_tcp_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp
    )
{
    /* TODO: unify iscsi + toe structure name */
    struct tstorm_toe_tcp_ag_context_section *ttcp_ag;
    struct tstorm_tcp_st_context_section *ttcp_st;
    l4_ofld_params_t *l4_params = &pdev->ofld_info.l4_params;
    lm_path_state_t *path = tcp->path;
    lm_neigh_state_t *neigh = path->neigh;
    u32_t sm_rtt, sm_delta;
    u32_t snd_wnd;

    ASSERT_STATIC(sizeof(struct tstorm_toe_tcp_ag_context_section) == sizeof(struct tstorm_tcp_tcp_ag_context_section) );
    if (tcp->ulp_type == TOE_CONNECTION_TYPE)
    {
        ttcp_ag = &((struct toe_context *)tcp->ctx_virt)->tstorm_ag_context.tcp;
        ttcp_st = &((struct toe_context *)tcp->ctx_virt)->tstorm_st_context.context.tcp;
    }
    else
    {
        ttcp_ag = (struct tstorm_toe_tcp_ag_context_section *)&((struct iscsi_context *)tcp->ctx_virt)->tstorm_ag_context.tcp;
        ttcp_st = &((struct iscsi_context *)tcp->ctx_virt)->tstorm_st_context.tcp;
    }
    mm_mem_zero(ttcp_ag, sizeof(struct tstorm_toe_tcp_ag_context_section));
    mm_mem_zero(ttcp_st, sizeof(struct tstorm_tcp_st_context_section));

    /* tstorm_ag_context */
    ttcp_ag->snd_max      = tcp->tcp_delegated.send_max;
    ttcp_ag->snd_nxt      = tcp->tcp_delegated.send_next;
    ttcp_ag->snd_una      = tcp->tcp_delegated.send_una;

    /* tstorm_st_context*/
    // starting FW 7.6.5, the DA_EN is a "don't care" for iSCSI as it is set in pf init to FW
    // iSCSI FW overrides this flag according to pf init value regardless context init here.
    ttcp_st->flags2 |= TSTORM_TCP_ST_CONTEXT_SECTION_DA_EN;         /* DA timer always on */

    // DA_COUNTER_EN should stay always on since FW will not use it in case DA_EN is off.
    ttcp_st->flags2 |= TSTORM_TCP_ST_CONTEXT_SECTION_DA_COUNTER_EN; /* DA counter always on */
    ttcp_st->dup_ack_count = tcp->tcp_delegated.dup_ack_count;

    if(tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP) {
        ttcp_st->flags1 |= TSTORM_TCP_ST_CONTEXT_SECTION_TIMESTAMP_EXISTS;
    }
    if(tcp->tcp_cached.tcp_flags & TCP_FLAG_ENABLE_KEEP_ALIVE) {
        ttcp_st->flags1 |= TSTORM_TCP_ST_CONTEXT_SECTION_KA_ENABLED;
        if ((tcp->tcp_cached.ka_time_out == 0) ||
            (tcp->tcp_cached.ka_interval == 0))
        {
            DbgBreakIf(tcp->tcp_cached.ka_time_out == 0);
            DbgBreakIf(tcp->tcp_cached.ka_interval == 0);
            return LM_STATUS_INVALID_PARAMETER;
        }
    }
    if(tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_WIN_SCALING) {
        ttcp_st->snd_wnd_scale = tcp->tcp_const.snd_seg_scale;
    }

    ttcp_st->cwnd                 = tcp->tcp_delegated.send_cwin - tcp->tcp_delegated.send_una; /* i.e. ndis_tcp_delegated->CWnd */
    /* bugbug: driver workaround - wnd may be 0xffffffff, in this case we change it to 2^30 - since FW has an assumption this value
     * doesn't wrap-around, configuring it to 0xffffffff may cause it to wrap around and then change from a very large cwnd to a ver
     * small one - we give 2^30 which is the largest cwnd that can be advertised.  */
    if (ttcp_st->cwnd == 0xffffffff) {
        ttcp_st->cwnd = 0x40000000;
    }

    ttcp_st->ka_interval          =
        lm_time_resolution(pdev, tcp->tcp_cached.ka_interval, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC);
    ttcp_st->ka_max_probe_count   = tcp->tcp_cached.ka_probe_cnt;
    if(tcp->tcp_delegated.send_una == tcp->tcp_delegated.send_max) { /* KA is running (?) */
        ttcp_st->ka_probe_count   = tcp->tcp_delegated.u.keep_alive.probe_cnt;
    } else {   /* retransmit is running (?) */
        ttcp_st->ka_probe_count   = 0;
    }
    ttcp_st->ka_timeout           =
        lm_time_resolution(pdev, tcp->tcp_cached.ka_time_out, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC);

    /* Set the src mac addr in tstorm context:
     * In both big and little endian architectures, the mac addr is given from the client in an array of
     * 6 chars. Therefore, regardless the endian architectue, we need to swap this array into the little endian
     * convention of the tstorm context. */
    ttcp_st->msb_mac_address = mm_cpu_to_le16(NTOH16(*(u16 *)(&neigh->neigh_const.src_addr[0])));
    ttcp_st->mid_mac_address = mm_cpu_to_le16(NTOH16(*(u16 *)(&neigh->neigh_const.src_addr[2])));
    ttcp_st->lsb_mac_address = mm_cpu_to_le16(NTOH16(*(u16 *)(&neigh->neigh_const.src_addr[4])));

    ttcp_st->max_rt_time          =
        lm_time_resolution(pdev, tcp->tcp_cached.max_rt, l4_params->ticks_per_second, TSEMI_CLK1_TICKS_PER_SEC);
    /* GilR: place holder, to be enabled in v0_18_1 when proper FW support is included */
    //ttcp_st->max_seg_retransmit_en = 0;
    if (ttcp_st->max_rt_time == 0) { /* GilR 9/19/2006 - TBD - currently FW does not handle the '0' case correctly. */
        ttcp_st->max_rt_time = 0xffffffff;
        ttcp_st->flags1 |= TSTORM_TCP_ST_CONTEXT_SECTION_MAX_SEG_RETRANSMIT_EN;
        //ctx->tstorm_st_context.tcp.max_seg_retransmit_en = 1;
    }

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        if (tcp->rx_con->u.rx.sws_info.mss > 0xffff)
        {
            DbgBreakIf(tcp->rx_con->u.rx.sws_info.mss > 0xffff);
            return LM_STATUS_INVALID_PARAMETER;
        }
        ttcp_st->mss = tcp->rx_con->u.rx.sws_info.mss & 0xffff;
    } else {
        /* we must calc mss here since it is possible that we don't have rx_con (iscsi) */
        ttcp_st->mss = _lm_tcp_calc_mss(tcp->path->path_cached.path_mtu,
                                    tcp->tcp_const.remote_mss,
                                    (tcp->path->path_const.ip_version == IP_VERSION_IPV6),
                                    tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP,
                                    pdev->ofld_info.l4_params.flags & OFLD_PARAM_FLAG_SNAP_ENCAP,
                                    tcp->path->neigh->neigh_const.vlan_tag  != 0) & 0xffff;

        /* NirV: set expected release sequance parameter that's being set in the toe fw but not in the iscsi fw */
        /* should be done in the iscsi initiate offload handler in the fw as in toe */
        ttcp_st->expected_rel_seq = tcp->tcp_delegated.send_una;
    }

    DbgMessage(pdev, INFORMl4sp, "offload num_retx=%d, snd_wnd_probe_cnt=%d\n",tcp->tcp_delegated.u.retransmit.num_retx,tcp->tcp_delegated.snd_wnd_probe_count);

    ttcp_st->persist_probe_count  = tcp->tcp_delegated.snd_wnd_probe_count;
    ttcp_st->prev_seg_seq         = tcp->tcp_delegated.send_wl1;
    ttcp_st->rcv_nxt              = tcp->tcp_delegated.recv_next;
    /*ttcp_st->reserved_slowpath    = 0;  This value is the 7 LSBs of the toeplitz hash result for this connection's 4 tuple.
                                                                    required in order to give the L2-completion on the correct RSS ring
                                                                    TBD - toeplitz hash calc not implemented for this yet, but no harm done */

    //calculate snd window
    snd_wnd = (S32_SUB(tcp->tcp_delegated.send_cwin, tcp->tcp_delegated.send_win) > 0) ?
        (tcp->tcp_delegated.send_win - tcp->tcp_delegated.send_una) : /* i.e. ndis_tcp_delegated->SndWnd */
        (tcp->tcp_delegated.send_cwin - tcp->tcp_delegated.send_una); /* i.e. ndis_tcp_delegated->CWnd */

    if(tcp->tcp_delegated.send_una == tcp->tcp_delegated.send_max && snd_wnd > 0) { /* KA is running (?) */
        ttcp_st->rto_exp = 0;
        ttcp_st->retransmit_count = 0;
    } else {   /* retransmit is running (?) */
        ttcp_st->retransmit_count = tcp->tcp_delegated.u.retransmit.num_retx;
        ttcp_st->rto_exp = tcp->tcp_delegated.u.retransmit.num_retx;
    }
    ttcp_st->retransmit_start_time =
        lm_time_resolution(pdev, tcp->tcp_delegated.total_rt, l4_params->ticks_per_second, TSEMI_CLK1_TICKS_PER_SEC);

    /* convert to ms.
     * the /8 and /4 are a result of some shifts that MSFT does, these number were received from MSFT through emails and are
     * done the same in Teton. */
    sm_rtt = lm_time_resolution(pdev, tcp->tcp_delegated.sm_rtt, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC)/8;
    if (sm_rtt > 30000) {   /* reduce to 30sec */
        sm_rtt = 30000;
    }
    sm_delta = lm_time_resolution(pdev, tcp->tcp_delegated.sm_delta, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC)/4;
    if (sm_delta > 30000) {   /* reduce to 30sec */
        sm_delta = 30000;
    }

    ttcp_st->flags1 |= (sm_rtt << TSTORM_TCP_ST_CONTEXT_SECTION_RTT_SRTT_SHIFT);  /* given in ticks, no conversion is required */
    ttcp_st->flags2 |= (sm_delta << TSTORM_TCP_ST_CONTEXT_SECTION_RTT_VARIATION_SHIFT); /* given in ticks, no conversion is required */
    if ((tcp->ulp_type == TOE_CONNECTION_TYPE) && (tcp->rx_con->flags & TCP_REMOTE_FIN_RECEIVED)) {
        ttcp_st->flags1 |= TSTORM_TCP_ST_CONTEXT_SECTION_STOP_RX_PAYLOAD;
    }

    ttcp_st->ss_thresh            = tcp->tcp_delegated.ss_thresh;
    ttcp_st->timestamp_recent     = tcp->tcp_delegated.ts_recent;
    ttcp_st->timestamp_recent_time =
        lm_time_resolution(pdev, tcp->tcp_delegated.ts_recent_age, l4_params->ticks_per_second, TSEMI_CLK1_TICKS_PER_SEC);
    ttcp_st->vlan_id              = neigh->neigh_const.vlan_tag;
    ttcp_st->recent_seg_wnd       = tcp->tcp_delegated.send_win - tcp->tcp_delegated.send_una;
    ttcp_st->ooo_support_mode      = (tcp->ulp_type == TOE_CONNECTION_TYPE)? TCP_TSTORM_OOO_SUPPORTED : TCP_TSTORM_OOO_DROP_AND_PROC_ACK;
    ttcp_st->statistics_counter_id = (tcp->ulp_type == TOE_CONNECTION_TYPE)? LM_STATS_CNT_ID(pdev) : LM_CLI_IDX_ISCSI;

    // Set statistics params
    if( TOE_CONNECTION_TYPE == tcp->ulp_type )
    {
        // set enable L2
        SET_FLAGS( ttcp_st->flags2, 1<<TSTORM_TCP_ST_CONTEXT_SECTION_UPDATE_L2_STATSTICS_SHIFT );

        // set enable L4
        SET_FLAGS( ttcp_st->flags2, 1<<TSTORM_TCP_ST_CONTEXT_SECTION_UPDATE_L4_STATSTICS_SHIFT );
    }

    return LM_STATUS_SUCCESS;
}


static lm_status_t _lm_tcp_init_xstorm_tcp_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    /* TODO: unify iscsi + toe structure name */
    struct xstorm_toe_tcp_ag_context_section * xtcp_ag;
    struct xstorm_common_context_section     * xtcp_st;
    lm_path_state_t  * path  = tcp->path;
    lm_neigh_state_t * neigh = path->neigh;
    l4_ofld_params_t * l4_params = &(pdev->ofld_info.l4_params);
    u32_t src_ip[4], dst_ip[4];
    u16_t pseudo_cs, i;
    u32_t sm_rtt, sm_delta;

    ASSERT_STATIC(sizeof(struct xstorm_toe_tcp_ag_context_section) == sizeof(struct xstorm_tcp_tcp_ag_context_section));
    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        xtcp_ag = &((struct toe_context *)tcp->ctx_virt)->xstorm_ag_context.tcp;
        xtcp_st = &((struct toe_context *)tcp->ctx_virt)->xstorm_st_context.context.common;
    } else {
        xtcp_ag = (struct xstorm_toe_tcp_ag_context_section *)&((struct iscsi_context *)tcp->ctx_virt)->xstorm_ag_context.tcp;
        xtcp_st = &((struct iscsi_context *)tcp->ctx_virt)->xstorm_st_context.common;
    }

    mm_mem_zero(xtcp_ag, sizeof(struct xstorm_toe_tcp_ag_context_section));
    mm_mem_zero(xtcp_st, sizeof(struct xstorm_common_context_section));

    xtcp_ag->ack_to_far_end       = tcp->tcp_delegated.recv_next;
    if(tcp->tcp_delegated.send_una == tcp->tcp_delegated.send_max) { /* KA is running (?) */
        if ((tcp->tcp_cached.ka_probe_cnt > 0) && (tcp->tcp_delegated.u.keep_alive.timeout_delta == 0)) {
            xtcp_ag->ka_timer = 1;
        } else if ((tcp->tcp_cached.ka_probe_cnt == 0) && (tcp->tcp_delegated.u.keep_alive.timeout_delta == 0)) {
            if (tcp->tcp_cached.ka_time_out == 0) {/* KA disabled */
                xtcp_ag->ka_timer = 0xffffffff;
            } else {
                if (tcp->tcp_cached.ka_time_out == 0xffffffff) {
                    xtcp_ag->ka_timer  = 0xffffffff;
                } else {
                    xtcp_ag->ka_timer =
                        tcp->tcp_cached.ka_time_out ?
                        lm_time_resolution(pdev, tcp->tcp_cached.ka_time_out, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC) :
                        1 /* value of 0 is not allowed by FW */;
                }
            }
        } else {
            if (tcp->tcp_delegated.u.keep_alive.timeout_delta == 0xffffffff) {
                xtcp_ag->ka_timer  = 0xffffffff;
            } else {
                xtcp_ag->ka_timer = lm_time_resolution(pdev, tcp->tcp_delegated.u.keep_alive.timeout_delta, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC);
            }
        }
    } else {   /* retransmit is running (?) */
        xtcp_ag->ka_timer         = 0xffffffff;
    }

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        xtcp_ag->local_adv_wnd        = tcp->tcp_delegated.recv_win_seq;
    } else if (tcp->ulp_type == ISCSI_CONNECTION_TYPE) {
        /* NirV: Add define to the iscsi HSI */
        xtcp_ag->local_adv_wnd        = 0xFFFF << ((u16_t)tcp->tcp_const.rcv_seg_scale & 0xf); /* rcv_seg_scale is only 4b long */
    }

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        if (tcp->rx_con->u.rx.sws_info.mss > 0xffff)
        {
            DbgBreakIf(tcp->rx_con->u.rx.sws_info.mss > 0xffff);
            return LM_STATUS_INVALID_PARAMETER;
        }
        xtcp_ag->mss = tcp->rx_con->u.rx.sws_info.mss & 0xffff;
    } else {
        /* we must calc mss here since it is possible that we don't have rx_con (iscsi) */
        xtcp_ag->mss = _lm_tcp_calc_mss(tcp->path->path_cached.path_mtu,
                                    tcp->tcp_const.remote_mss,
                                    (tcp->path->path_const.ip_version == IP_VERSION_IPV6),
                                    tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP,
                                    pdev->ofld_info.l4_params.flags & OFLD_PARAM_FLAG_SNAP_ENCAP,
                                    tcp->path->neigh->neigh_const.vlan_tag  != 0) & 0xfffc;     /* MSS value set in the XStorm should be multiple of 4 */

        if (tcp->ulp_type == ISCSI_CONNECTION_TYPE)
        {
            if (xtcp_ag->mss < 4)
            {
                DbgBreakIf(xtcp_ag->mss < 4);
                return LM_STATUS_INVALID_PARAMETER;
            }
            xtcp_ag->mss -= 4;  // -4 for data digest
        }
    }

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        /*if persist probes were sent xstorm should be blocked*/
        if (tcp->tcp_delegated.snd_wnd_probe_count == 0) {
            xtcp_ag->tcp_agg_vars2 |= __XSTORM_TOE_TCP_AG_CONTEXT_SECTION_TX_UNBLOCKED;
        }
    }

    /* calculate transmission window */
    xtcp_ag->tx_wnd               =
        (S32_SUB(tcp->tcp_delegated.send_cwin, tcp->tcp_delegated.send_win) > 0) ?
        (tcp->tcp_delegated.send_win - tcp->tcp_delegated.send_una) : /* i.e. ndis_tcp_delegated->SndWnd */
        (tcp->tcp_delegated.send_cwin - tcp->tcp_delegated.send_una); /* i.e. ndis_tcp_delegated->CWnd */

    /* bugbug: driver workaround - wnd may be 0xffffffff, in this case we change it to 2^30 - since FW has an assumption this value
     * doesn't wrap-around, configuring it to 0xffffffff may cause it to wrap around and then change from a very large cwnd to a ver
     * small one - we give 2^30 which is the largest cwnd that can be advertised.  */
    if (xtcp_ag->tx_wnd == 0xffffffff) {
        xtcp_ag->tx_wnd = 0x40000000;
    }

    /* check if we are in keepalive. */
    if ((tcp->tcp_delegated.send_una == tcp->tcp_delegated.send_max) && ((xtcp_ag->tx_wnd > 0) || (tcp->tcp_delegated.u.retransmit.retx_ms == 0xffffffff))) { /* KA is enabled (?) */
       /* convert to ms.
        * the /8 and /4 are a result of some shifts that MSFT does, these number were received from MSFT through emails and are
        * done the same in Teton. */
        sm_rtt = lm_time_resolution(pdev, tcp->tcp_delegated.sm_rtt, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC)/8;
        if (sm_rtt > 30000) {   /* reduce to 30sec */
            sm_rtt = 30000;
        }
        sm_delta = lm_time_resolution(pdev, tcp->tcp_delegated.sm_delta, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC)/4;
        if (sm_delta > 30000) { /* reduce to 30sec */
            sm_delta = 30000;
        }
        xtcp_ag->rto_timer  = (sm_rtt + (sm_delta << 2));
    } else {   /* retransmit is running (?) */
        if (tcp->tcp_delegated.u.retransmit.retx_ms == 0xffffffff) {
            xtcp_ag->rto_timer       = 0xffffffff;
        } else {
            xtcp_ag->rto_timer        = tcp->tcp_delegated.u.retransmit.retx_ms ? tcp->tcp_delegated.u.retransmit.retx_ms : 1 /* value of 0 is not allowed by FW*/;
                /* TODO: retx_ms is already converted in Miniport
                 * we need to convert retx_ms to clock ticks in VBD instead of
                 * doing this conversion in NDIS (same as Teton) */
                /*tcp->tcp_delegated.u.retransmit.retx_ms ?
                lm_time_resolution(pdev, tcp->tcp_delegated.u.retransmit.retx_ms,
                                   1000, TIMERS_TICKS_PER_SEC) :
                1 *//* value of 0 is not allowed by FW*/;
        }
    }
    xtcp_ag->snd_nxt              = tcp->tcp_delegated.send_next;
    xtcp_ag->snd_una              = tcp->tcp_delegated.send_una;
    xtcp_ag->tcp_agg_vars2        |= XSTORM_TOE_TCP_AG_CONTEXT_SECTION_DA_ENABLE; /* Delayed Acks always on */
    xtcp_ag->ts_to_echo           = tcp->tcp_delegated.ts_recent;


    /* xstorm_st_context */
    xtcp_st->ethernet.remote_addr_0      = neigh->neigh_cached.dst_addr[0];
    xtcp_st->ethernet.remote_addr_1      = neigh->neigh_cached.dst_addr[1];
    xtcp_st->ethernet.remote_addr_2      = neigh->neigh_cached.dst_addr[2];
    xtcp_st->ethernet.remote_addr_3      = neigh->neigh_cached.dst_addr[3];
    xtcp_st->ethernet.remote_addr_4      = neigh->neigh_cached.dst_addr[4];
    xtcp_st->ethernet.remote_addr_5      = neigh->neigh_cached.dst_addr[5];

    if (neigh->neigh_const.vlan_tag > 0xfff)
    {
        DbgBreakIf(neigh->neigh_const.vlan_tag > 0xfff);
        return LM_STATUS_INVALID_PARAMETER;
    }
    xtcp_st->ethernet.vlan_params |= (neigh->neigh_const.vlan_tag << XSTORM_ETH_CONTEXT_SECTION_VLAN_ID_SHIFT);

    if (tcp->tcp_cached.user_priority > 0x7)
    {
        DbgBreakIf(tcp->tcp_cached.user_priority > 0x7);
        return LM_STATUS_INVALID_PARAMETER;
    }
    xtcp_st->ethernet.vlan_params  |= (tcp->tcp_cached.user_priority << XSTORM_ETH_CONTEXT_SECTION_PRIORITY_SHIFT);

    if ((0 != GET_FLAGS(xtcp_st->ethernet.vlan_params, XSTORM_ETH_CONTEXT_SECTION_VLAN_ID)) ||
        (0 != GET_FLAGS(xtcp_st->ethernet.vlan_params, XSTORM_ETH_CONTEXT_SECTION_CFI))     ||
        (0 != GET_FLAGS(xtcp_st->ethernet.vlan_params, XSTORM_ETH_CONTEXT_SECTION_PRIORITY)))
    {
        // This fields should be set to 1 whenever an inner VLAN is provided by the OS. 
        // This flags is relevant for all function modes.
        SET_FLAGS( xtcp_st->flags, XSTORM_COMMON_CONTEXT_SECTION_VLAN_MODE);
    }

    xtcp_st->ethernet.local_addr_0   = neigh->neigh_const.src_addr[0];
    xtcp_st->ethernet.local_addr_1   = neigh->neigh_const.src_addr[1];
    xtcp_st->ethernet.local_addr_2   = neigh->neigh_const.src_addr[2];
    xtcp_st->ethernet.local_addr_3   = neigh->neigh_const.src_addr[3];
    xtcp_st->ethernet.local_addr_4   = neigh->neigh_const.src_addr[4];
    xtcp_st->ethernet.local_addr_5   = neigh->neigh_const.src_addr[5];
    xtcp_st->ethernet.reserved_vlan_type = 0x8100;

    xtcp_st->ip_version_1b           = (tcp->path->path_const.ip_version == IP_VERSION_IPV4)? 0 : 1;
    if (tcp->path->path_const.ip_version == IP_VERSION_IPV4) {
        /* IPv4*/
        xtcp_st->ip_union.padded_ip_v4.ip_v4.ip_remote_addr      = path->path_const.u.ipv4.dst_ip;
        xtcp_st->ip_union.padded_ip_v4.ip_v4.ip_local_addr       = path->path_const.u.ipv4.src_ip;
        xtcp_st->ip_union.padded_ip_v4.ip_v4.tos                 = tcp->tcp_cached.tos_or_traffic_class;
#if DBG
        xtcp_st->ip_union.padded_ip_v4.ip_v4.ttl                 = (tcp->ulp_type == TOE_CONNECTION_TYPE) ? TOE_DBG_TTL : ISCSI_DBG_TTL;
#else
        xtcp_st->ip_union.padded_ip_v4.ip_v4.ttl                 = tcp->tcp_cached.ttl_or_hop_limit;
#endif
        src_ip[0] = HTON32(path->path_const.u.ipv4.src_ip);
        dst_ip[0] = HTON32(path->path_const.u.ipv4.dst_ip);
        pseudo_cs = lm_tcp_calc_tcp_pseudo_checksum(pdev, src_ip, dst_ip, IP_VERSION_IPV4);       
    } else {
        /* IPv6*/
        xtcp_st->ip_union.ip_v6.ip_remote_addr_lo_lo = path->path_const.u.ipv6.dst_ip[0];
        xtcp_st->ip_union.ip_v6.ip_remote_addr_lo_hi = path->path_const.u.ipv6.dst_ip[1];
        xtcp_st->ip_union.ip_v6.ip_remote_addr_hi_lo = path->path_const.u.ipv6.dst_ip[2];
        xtcp_st->ip_union.ip_v6.ip_remote_addr_hi_hi = path->path_const.u.ipv6.dst_ip[3];

        xtcp_st->ip_union.ip_v6.ip_local_addr_lo_lo  = path->path_const.u.ipv6.src_ip[0];
        xtcp_st->ip_union.ip_v6.ip_local_addr_lo_hi  = path->path_const.u.ipv6.src_ip[1];
        xtcp_st->ip_union.ip_v6.ip_local_addr_hi_lo  = path->path_const.u.ipv6.src_ip[2];
        xtcp_st->ip_union.ip_v6.ip_local_addr_hi_hi  = path->path_const.u.ipv6.src_ip[3];

#if DBG
        xtcp_st->ip_union.ip_v6.hop_limit                        = (tcp->ulp_type == TOE_CONNECTION_TYPE) ? TOE_DBG_TTL : ISCSI_DBG_TTL;
#else
        xtcp_st->ip_union.ip_v6.hop_limit                        = tcp->tcp_cached.ttl_or_hop_limit;
#endif
        DbgBreakIf(tcp->tcp_cached.flow_label > 0xffff);
        xtcp_st->ip_union.ip_v6.priority_flow_label =
            tcp->tcp_cached.flow_label << XSTORM_IP_V6_CONTEXT_SECTION_FLOW_LABEL_SHIFT |
            tcp->tcp_cached.tos_or_traffic_class << XSTORM_IP_V6_CONTEXT_SECTION_TRAFFIC_CLASS_SHIFT;

        for (i = 0; i < 4; i++) {
            src_ip[i] = HTON32(path->path_const.u.ipv6.src_ip[i]);
            dst_ip[i] = HTON32(path->path_const.u.ipv6.dst_ip[i]);
        }
        pseudo_cs = lm_tcp_calc_tcp_pseudo_checksum(pdev, src_ip, dst_ip, IP_VERSION_IPV6);
    }

    xtcp_st->tcp.local_port            = tcp->tcp_const.src_port;


    xtcp_st->tcp.pseudo_csum           = NTOH16(pseudo_cs);
    xtcp_st->tcp.remote_port           = tcp->tcp_const.dst_port;
    xtcp_st->tcp.snd_max               = tcp->tcp_delegated.send_max;
    if(tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP) {
        xtcp_st->tcp.ts_enabled  = 1;
    }
    if(tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_SACK) {
        xtcp_st->tcp.tcp_params |= XSTORM_TCP_CONTEXT_SECTION_SACK_ENABLED;
    }
    if ((tcp->ulp_type == TOE_CONNECTION_TYPE) && (tcp->tx_con->flags & TCP_FIN_REQ_POSTED)) {
        xtcp_st->tcp.tcp_params |= XSTORM_TCP_CONTEXT_SECTION_FIN_SENT_FLAG;
    }
    xtcp_st->tcp.ts_time_diff          = tcp->tcp_delegated.tstamp; /* time conversion not required */
    xtcp_st->tcp.window_scaling_factor = (u16_t)tcp->tcp_const.rcv_seg_scale & 0xf; /* rcv_seg_scale is only 4b long */

    // Set statistics params
    if( TOE_CONNECTION_TYPE == tcp->ulp_type )
    {
        // set counter id
        xtcp_st->tcp.statistics_counter_id = LM_STATS_CNT_ID(pdev);

        // set enable L2
        SET_FLAGS( xtcp_st->tcp.statistics_params, 1<<XSTORM_TCP_CONTEXT_SECTION_UPDATE_L2_STATSTICS_SHIFT );

        // set enable L4
        SET_FLAGS( xtcp_st->tcp.statistics_params, 1<<XSTORM_TCP_CONTEXT_SECTION_UPDATE_L4_STATSTICS_SHIFT );
    }
    if (tcp->ulp_type == ISCSI_CONNECTION_TYPE)
    {
        SET_FLAGS( xtcp_st->flags,(1 << XSTORM_COMMON_CONTEXT_SECTION_PHYSQ_INITIALIZED_SHIFT ));

        SET_FLAGS( xtcp_st->flags,(PORT_ID(pdev) << XSTORM_COMMON_CONTEXT_SECTION_PBF_PORT_SHIFT));
    }
    return LM_STATUS_SUCCESS;
}


/* init the content of the toe context */
static lm_status_t _lm_tcp_init_tcp_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    lm_status_t lm_status ;

    lm_status = _lm_tcp_init_xstorm_tcp_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    lm_status = _lm_tcp_init_tstorm_tcp_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_init_iscsi_tcp_related_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    struct cstorm_iscsi_ag_context * ciscsi_ag = &((struct iscsi_context *)tcp->ctx_virt)->cstorm_ag_context;
    struct cstorm_iscsi_st_context * ciscsi_st = &((struct iscsi_context *)tcp->ctx_virt)->cstorm_st_context;
    struct xstorm_iscsi_ag_context * xiscsi_ag = &((struct iscsi_context *)tcp->ctx_virt)->xstorm_ag_context;
    struct xstorm_iscsi_st_context * xiscsi_st = &((struct iscsi_context *)tcp->ctx_virt)->xstorm_st_context;
    struct tstorm_iscsi_ag_context * tiscsi_ag = &((struct iscsi_context *)tcp->ctx_virt)->tstorm_ag_context;
    struct tstorm_iscsi_st_context * tiscsi_st = &((struct iscsi_context *)tcp->ctx_virt)->tstorm_st_context;

    UNREFERENCED_PARAMETER_(pdev);

    ASSERT_STATIC(sizeof(struct cstorm_toe_ag_context) == sizeof(struct cstorm_iscsi_ag_context));
//  ASSERT_STATIC(sizeof(struct cstorm_toe_st_context) == sizeof(struct cstorm_iscsi_st_context));
//  ASSERT_STATIC(OFFSETOF(struct iscsi_context, cstorm_ag_context)== OFFSETOF(struct toe_context, cstorm_ag_context) ) ;
//  ASSERT_STATIC(OFFSETOF(struct iscsi_context, cstorm_st_context)== OFFSETOF(struct toe_context, cstorm_st_context) ) ;

    /* cstorm */
    ciscsi_ag->rel_seq      = tcp->tcp_delegated.send_next; //pTcpParams->sndNext;
    ciscsi_ag->rel_seq_th   = tcp->tcp_delegated.send_next; //pTcpParams->sndNext;
    ciscsi_st->hq_tcp_seq   = tcp->tcp_delegated.send_next; //pTcpParams->sndNext;

    /* xstorm */
    xiscsi_ag->hq_cons_tcp_seq = tcp->tcp_delegated.send_next; //pTcpParams->sndNext;

    /* tstorm */
    /* in toe the window right edge is initialized by the doorbell */
                                                 /* recv_win_seq */                                                             /* recv next */
    tiscsi_ag->tcp.wnd_right_edge = (xiscsi_ag->tcp.local_adv_wnd << xiscsi_st->common.tcp.window_scaling_factor) + xiscsi_ag->tcp.ack_to_far_end;

    tiscsi_ag->tcp.wnd_right_edge_local = tiscsi_ag->tcp.wnd_right_edge;

    tiscsi_st->iscsi.process_nxt = tcp->tcp_delegated.recv_next; // same value as rcv_nxt

    //xAgCtx->mss = pTcpParams->mss - 4; // -4 for data digest

    return LM_STATUS_SUCCESS;
}

/* Desciption:
 *  Allocation of CID for a new TCP connection to be offloaded,
 *  Initiation of connection's context line as required by FW.
 * Assumptions:
 *  - lm_tcp_init_tcp_state, lm_tcp_init_rx_con/tx_con already called
 *  - send unacked data already posted
 *  - If the TCP is in states FinWait1, Closing or LastAck,
 *    FIN is already posted to the tx chain
 *  - Called under connection lock: since it can be called from either initiate-ofld
 *    or recycle-cid (before ofld had the chance to complete)
 * Returns:
 *  SUCCESS or any failure */
static lm_status_t lm_tcp_init_tcp_context(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    s32_t cid;
    lm_status_t lm_status;
    lm_4tuple_t tuple = {{0}};
    u32_t expect_rwin;
    u8_t i;

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_init_tcp_context\n");

    /* NirV: allocate cid is getting back here */
    /* allocate cid only if cid==0: we may re-enter this function after a cid has already been allocated */
    if (tcp->cid == 0)
    {
        lm_status = lm_allocate_cid(pdev, TOE_CONNECTION_TYPE, (void*)tcp, &cid);
        if(lm_status == LM_STATUS_RESOURCE){
            DbgMessage(pdev, WARNl4sp, "lm_tcp_init_tcp_state: Failed in allocating cid\n");
            return LM_STATUS_RESOURCE;
        } else if (lm_status == LM_STATUS_PENDING) {
            lm_sp_req_manager_block(pdev, (u32_t)cid);
        }
        tcp->cid = (u32_t)cid;
    }

    if (lm_cid_state(pdev, tcp->cid) == LM_CID_STATE_PENDING) {
        return LM_STATUS_SUCCESS; /* Too soon to initialize context */
    }

    /* Validate some of the offload parameters - only relevant for TOE. */
    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        tcp->rx_con->u.rx.sws_info.extra_bytes = 0;
        if (tcp->rx_con->u.rx.gen_info.peninsula_nbytes > tcp->tcp_cached.initial_rcv_wnd) {
            tcp->rx_con->u.rx.sws_info.extra_bytes = tcp->rx_con->u.rx.gen_info.peninsula_nbytes - tcp->tcp_cached.initial_rcv_wnd;
            tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge = tcp->tcp_delegated.recv_next;
            tcp->rx_con->db_data.rx->rcv_win_right_edge = tcp->tcp_delegated.recv_next;
            DbgMessage(pdev, INFORMl4sp, "lm_tcp_init_tcp_state: pnb:%x, irw:%x, ext:%x, rnx:%x\n",tcp->rx_con->u.rx.gen_info.peninsula_nbytes,
                       tcp->tcp_cached.initial_rcv_wnd,tcp->rx_con->u.rx.sws_info.extra_bytes,tcp->tcp_delegated.recv_next);
        } else {
            expect_rwin = (u32_t)S32_SUB(
                tcp->tcp_delegated.recv_win_seq,
                tcp->tcp_delegated.recv_next);
            expect_rwin += tcp->rx_con->u.rx.gen_info.peninsula_nbytes;

        /* WorkAround for LH: fields received at offload should match the equation below,
         * In LH it's not the case. TBA: add assert that we are on LH operating system */
            DbgMessage(pdev, INFORMl4sp, "lm_tcp_init_tcp_state: pnb:%x, irw:%x, rws:%x, rnx:%x\n",tcp->rx_con->u.rx.gen_info.peninsula_nbytes,
                        tcp->tcp_cached.initial_rcv_wnd,
                        tcp->tcp_delegated.recv_win_seq,
                        tcp->tcp_delegated.recv_next);
            if (ERR_IF(expect_rwin != tcp->tcp_cached.initial_rcv_wnd)) {
                u32_t delta;
                /* move tcp_delegated.recv_next accordingly */
                if (expect_rwin > tcp->tcp_cached.initial_rcv_wnd) {
                    delta = expect_rwin - tcp->tcp_cached.initial_rcv_wnd;
                    tcp->tcp_delegated.recv_win_seq -= delta;
                } else {
                    delta = tcp->tcp_cached.initial_rcv_wnd - expect_rwin;
                    tcp->tcp_delegated.recv_win_seq += delta;
                }
                /* Need to also update the driver win right edge */
                tcp->rx_con->db_data.rx->rcv_win_right_edge = tcp->tcp_delegated.recv_win_seq;
                tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge = tcp->tcp_delegated.recv_win_seq;
            }
        }
    }
    /* insert 4 tuple to searcher's mirror hash */
    if(tcp->path->path_const.ip_version == IP_VERSION_IPV4) { /* IPV4 */
        tuple.ip_type = LM_IP_TYPE_V4;
        tuple.dst_ip[0] = tcp->path->path_const.u.ipv4.dst_ip;
        tuple.src_ip[0] = tcp->path->path_const.u.ipv4.src_ip;
    } else {
        tuple.ip_type = LM_IP_TYPE_V6;
        for (i = 0; i < 4; i++) {
            tuple.dst_ip[i] = tcp->path->path_const.u.ipv6.dst_ip[i];
            tuple.src_ip[i] = tcp->path->path_const.u.ipv6.src_ip[i];
        }
    }
    tuple.src_port = tcp->tcp_const.src_port;
    tuple.dst_port = tcp->tcp_const.dst_port;
    if (lm_searcher_mirror_hash_insert(pdev, tcp->cid, &tuple) != LM_STATUS_SUCCESS) {
        DbgMessage(pdev, WARNl4sp, "lm_tcp_init_tcp_context: Failed inserting tuple to SRC hash\n");
        tcp->in_searcher = 0;
        return LM_STATUS_RESOURCE;
    }
    tcp->in_searcher = 1;

    /* get context */
    tcp->ctx_virt = (struct toe_context *)lm_get_context(pdev, tcp->cid);
    if (!tcp->ctx_virt) {
        DbgBreakIf(!tcp->ctx_virt);
        return LM_STATUS_FAILURE;
    }

    tcp->ctx_phys.as_u64 = lm_get_context_phys(pdev, tcp->cid);
    if (!tcp->ctx_phys.as_u64) {
        DbgBreakIf(!tcp->ctx_phys.as_u64);
        return LM_STATUS_FAILURE;
    }
    DbgMessage(pdev, VERBOSEl4sp,
                "tcp->ctx_virt=%p, tcp->ctx_phys_high=%x, tcp->ctx_phys_low=%x\n",
                tcp->ctx_virt, tcp->ctx_phys.as_u32.high, tcp->ctx_phys.as_u32.low);

    /* init the content of the context */
    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        lm_status = _lm_tcp_init_toe_context(pdev, tcp);
        if (lm_status != LM_STATUS_SUCCESS) {
            return lm_status;
        }
    }

    lm_status = _lm_tcp_init_tcp_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    /* iscsi / toe contexts are initialized separately, only the tcp section is common, HOWEVER, in iscsi
     * most of the context is initialized in the l5_ofld_stage, but some of the context initialization is based on tcp
     * params, that's why we need to complete it here...  */
    if (tcp->ulp_type == ISCSI_CONNECTION_TYPE) {
        lm_status = _lm_tcp_init_iscsi_tcp_related_context(pdev, tcp);
        if (lm_status != LM_STATUS_SUCCESS) {
            return lm_status;
        }
    }

    return LM_STATUS_SUCCESS;
}

/** Description
 *  Callback function for cids being recylced
 */
void lm_tcp_recycle_cid_cb(
    struct _lm_device_t *pdev,
    void *cookie,
    s32_t cid)
{
    lm_tcp_state_t       *tcp    = (lm_tcp_state_t *)cookie;
    lm_sp_req_common_t   *sp_req = NULL;
    MM_ACQUIRE_TOE_LOCK(pdev);

    /* un-block the manager... */
    lm_set_cid_state(pdev, tcp->cid, LM_CID_STATE_VALID);

    /* if the ofld flow got to the ofld workitem, only now set we can use the context,
       other wise, we'll get to the init_tcp_context later on */
    if (tcp->hdr.status == STATE_STATUS_INIT_CONTEXT)
    {
        lm_tcp_init_tcp_context(pdev,tcp);
    }

    /* we can now unblock any pending slow-paths */
    lm_sp_req_manager_unblock(pdev,cid, &sp_req);


    MM_RELEASE_TOE_LOCK(pdev);
}

/* This function needs to complete a pending slowpath toe request. Unfortunatelly it needs
 * to take care of all the steps done in lm_toe_service_rx_intr and lm_toe_service_tx_intr,
 * process the cqe, and complete slowpath...
 */
void lm_tcp_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command *pending)
{
    lm_tcp_state_t  * tcp    = NULL;
    lm_tcp_con_t    * rx_con = NULL;
    lm_tcp_con_t    * tx_con = NULL;
    struct toe_rx_cqe rx_cqe = {0};
    struct toe_tx_cqe tx_cqe = {0};
    u8_t              i      = 0;
    u8_t              cmp_rx = FALSE;
    u8_t              cmp_tx = FALSE;

    MM_INIT_TCP_LOCK_HANDLE();

    tcp = lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, pending->cid);
    /* Possible the tcp is NULL for ramrods that are context-less (RSS for example) */
    if (tcp)
    {
        rx_con = tcp->rx_con;
        tx_con = tcp->tx_con;
    }

    #define LM_TCP_SET_CQE(_param, _cid, _cmd) \
        (_param) = (((_cid) << TOE_RX_CQE_CID_SHIFT) & TOE_RX_CQE_CID) | \
                   (((_cmd) << TOE_RX_CQE_COMPLETION_OPCODE_SHIFT) & TOE_RX_CQE_COMPLETION_OPCODE);

    switch (pending->cmd)
    {
    case RAMROD_OPCODE_TOE_INIT:
        DbgBreakMsg("Not Supported\n");
        break;
    case RAMROD_OPCODE_TOE_INITIATE_OFFLOAD:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_INITIATE_OFFLOAD);
        cmp_rx = TRUE;
        break;
    case RAMROD_OPCODE_TOE_SEARCHER_DELETE:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_SEARCHER_DELETE);
        cmp_rx = TRUE;
        break;
    case RAMROD_OPCODE_TOE_TERMINATE:
        /* Completion may have completed on tx / rx only, so whether or not to complete it depends not
         * only on type but on state of sp_request as well... */
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_TERMINATE);
        cmp_rx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_RX) == 0);
        LM_TCP_SET_CQE(tx_cqe.params, pending->cid, RAMROD_OPCODE_TOE_TERMINATE);
        cmp_tx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_TX) == 0);;
        break;
    case RAMROD_OPCODE_TOE_QUERY:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_QUERY);
        cmp_rx = TRUE;
        break;
    case RAMROD_OPCODE_TOE_RESET_SEND:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_RESET_SEND);
        cmp_rx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_RX) == 0);
        LM_TCP_SET_CQE(tx_cqe.params, pending->cid, RAMROD_OPCODE_TOE_RESET_SEND);
        cmp_tx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_TX) == 0);
        break;
    case RAMROD_OPCODE_TOE_EMPTY_RAMROD:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_EMPTY_RAMROD);
        cmp_rx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_RX) == 0);
        LM_TCP_SET_CQE(tx_cqe.params, pending->cid, RAMROD_OPCODE_TOE_EMPTY_RAMROD);
        cmp_tx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_TX) == 0);
        break;
    case RAMROD_OPCODE_TOE_INVALIDATE:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_INVALIDATE);
        cmp_rx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_RX) == 0);
        LM_TCP_SET_CQE(tx_cqe.params, pending->cid, RAMROD_OPCODE_TOE_INVALIDATE);
        cmp_tx = (GET_FLAGS(tcp->sp_flags, SP_REQUEST_COMPLETED_TX) == 0);
        break;
    case RAMROD_OPCODE_TOE_UPDATE:
        LM_TCP_SET_CQE(rx_cqe.params1, pending->cid, RAMROD_OPCODE_TOE_UPDATE);
        cmp_rx = TRUE;
        break;
    case RAMROD_OPCODE_TOE_RSS_UPDATE:
        /* This one is special, its not treated as other ramrods, we return and not break
         * at the end of this one... */
        /* a bit of a hack here... we only want to give one completion and not on all
         * rcq-chains, so we update the counters and decrease all l4 rss chains
         * except one. then we give the completion to just one chain which should take care
         * of completing the sq and if L2 ramrod has completed already it will also comp
         * back to OS */
        for (i = 0; i < pdev->params.l4_rss_chain_cnt-1; i++)
        {
            mm_atomic_dec(&pdev->params.update_toe_comp_cnt);
            mm_atomic_dec(&pdev->params.update_comp_cnt);
            mm_atomic_dec(&pdev->params.update_suspend_cnt);
        }
        lm_tcp_rss_update_ramrod_comp(pdev,
                                      &pdev->toe_info.rcqs[LM_TOE_BASE_RSS_ID(pdev)],
                                      pending->cid,
                                      TOE_RSS_UPD_QUIET /* doesn't really matter*/,
                                      TRUE);

        return;
    }
    /* process the cqes and initialize connections with all the connections that appeared
     * in the DPC */
    if (cmp_rx)
    {
        lm_tcp_rx_process_cqe(pdev, &rx_cqe, tcp, 0 /* d/c for slpowpath */);
        /* FP: no need to call complete_tcp_fp since we're only completing slowpath, but we do
         * need to  move the flags for sake of next function */
        rx_con->dpc_info.snapshot_flags = rx_con->dpc_info.dpc_flags;
        rx_con->dpc_info.dpc_flags = 0;

        /* we access snapshot and not dpc, since once the dpc_flags were copied
         * to snapshot they were zeroized */
        lm_tcp_rx_complete_tcp_sp(pdev, tcp, rx_con);
    }

    /* process the cqes and initialize connections with all the connections that appeared
     * in the DPC */
    if (cmp_tx)
    {
        lm_tcp_tx_process_cqe(pdev, &tx_cqe, tcp);
        /* FP: no need to call complete_tcp_fp since we're only completing slowpath, but we do
         * need to  move the flags for sake of next function */
        tx_con->dpc_info.snapshot_flags = tx_con->dpc_info.dpc_flags;
        tx_con->dpc_info.dpc_flags = 0;

        /* we access snapshot and not dpc, since once the dpc_flags were copied
         * to snapshot they were zeroized */
        lm_tcp_tx_complete_tcp_sp(pdev, tcp, tx_con);
    }

}

/* Desciption:
 *  - init TCP state according to its TCP state machine's state
 * Assumptions:
 *  - lm_tcp_init_tcp_state, lm_tcp_init_rx_con/tx_con already called
 *  - send unacked data already posted
 * Returns:
 *  SUCCESS or any failure */
static lm_status_t lm_tcp_init_tcp_state_machine(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    lm_tcp_con_t                *con        = tcp->rx_con;
    lm_tcp_state_calculation_t  *state_calc = &tcp->tcp_state_calc;
    u64_t                       curr_time   = 0;
    lm_status_t                 lm_status   = LM_STATUS_SUCCESS;

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_init_tcp_state_machine\n");

    /* initiate times in the state calculation struct
      according to delegated.con_state */

    state_calc->fin_request_time = state_calc->fin_completed_time =
        state_calc->fin_reception_time = 0;
    curr_time = mm_get_current_time(pdev);

    switch (tcp->tcp_delegated.con_state) {
    case L4_TCP_CON_STATE_ESTABLISHED:
        break;
    case L4_TCP_CON_STATE_FIN_WAIT1:
        DbgMessage(pdev, WARNl4sp, "#tcp state offloaded in state FIN_WAIT1 (tcp=%p)\n", tcp);
        state_calc->fin_request_time = curr_time;
        break;
    case L4_TCP_CON_STATE_FIN_WAIT2:
        DbgMessage(pdev, WARNl4sp, "#tcp state offloaded in state FIN_WAIT2 (tcp=%p)\n", tcp);
        state_calc->fin_request_time = curr_time - 1;
        state_calc->fin_completed_time = curr_time;
        break;
    case L4_TCP_CON_STATE_CLOSE_WAIT:
        DbgMessage(pdev, WARNl4sp, "#tcp state offloaded in state CLOSE_WAIT (tcp=%p)\n", tcp);
        state_calc->fin_reception_time = curr_time;
        break;
    case L4_TCP_CON_STATE_CLOSING:
        DbgMessage(pdev, WARNl4sp, "#tcp state offloaded in state CLOSING (tcp=%p)\n", tcp);
        state_calc->fin_request_time = curr_time - 1;
        state_calc->fin_reception_time = curr_time;
        break;
    case L4_TCP_CON_STATE_LAST_ACK:
        DbgMessage(pdev, WARNl4sp, "#tcp state offloaded in state LAST_ACK (tcp=%p)\n", tcp);
        state_calc->fin_reception_time = curr_time - 1;
        state_calc->fin_request_time = curr_time;
        break;
    default:
        DbgMessage(pdev, FATAL,
                    "Initiate offload in con state=%d is not allowed by WDK!\n",
                    tcp->tcp_delegated.con_state);
        DbgBreak();
        return LM_STATUS_FAILURE;
    }

    /* In case the the TCP state is CloseWait, Closing or LastAck, the Rx con
     * should be initiated as if remote FIN was already received */

    if (state_calc->fin_reception_time) {
        /* remote FIN was already received */
        DbgBreakIf(con->flags & TCP_REMOTE_FIN_RECEIVED);
        con->flags |= TCP_REMOTE_FIN_RECEIVED;

        if (con->flags & TCP_INDICATE_REJECTED) {
            /* GilR: TODO - is this case really possible [fin received+buffered data given]? If so, does NDIS really expect the fin received indication? */
            /* buffered data exists, defer FIN indication */
            con->u.rx.flags |= TCP_CON_FIN_IND_PENDING;
        } else {
            /* no buffered data, simulate that remote FIN already indicated */
            con->flags |= TCP_REMOTE_FIN_RECEIVED_ALL_RX_INDICATED;
            con->flags |= TCP_BUFFERS_ABORTED;
        }
    }

    con = tcp->tx_con;
    /* check if local FIN was already sent, and if it was acknowledged */
    if (state_calc->fin_completed_time) {
        /* FIN already sent and acked */
        volatile struct toe_tx_db_data *db_data = con->db_data.tx;
        DbgBreakIf(!state_calc->fin_request_time);
        DbgBreakIf(!s_list_is_empty(&con->active_tb_list));
        con->flags |= (TCP_FIN_REQ_POSTED | TCP_FIN_REQ_COMPLETED);
        db_data->flags |= (TOE_TX_DB_DATA_FIN << TOE_TX_DB_DATA_FIN_SHIFT);
        db_data->bytes_prod_seq--;
    } else if (state_calc->fin_request_time) {
        /* FIN was already sent but not acked */

        /* GilR 11/12/2006 - TODO - we do not take the tx lock here, verify that its ok... */
        /* We want to make sure we'll be able to post the tcp buffer but
         * NOT ring the doorbell */
        DbgBreakIf(con->flags & TCP_DB_BLOCKED);
        con->flags |= TCP_DB_BLOCKED;
        DbgBreakIf(!(con->flags & TCP_POST_BLOCKED));
        con->flags &= ~TCP_POST_BLOCKED; /* posting is temporary allowed */

        con->u.tx.flags |= TCP_CON_FIN_REQ_LM_INTERNAL;
        lm_status = lm_tcp_graceful_disconnect(pdev, tcp);
        DbgBreakIf(lm_status != LM_STATUS_SUCCESS);

        /* retrieve initial state */
        con->flags &= ~TCP_DB_BLOCKED;
        con->flags |= TCP_POST_BLOCKED; /* posting is no longer allowed*/
    }

    return LM_STATUS_SUCCESS;
}


/* Desciption:
 *  - call lm_tcp_init_tcp_state_machine
 *  - call lm_tcp_init_tcp_context
 * Assumptions:
 *  - lm_tcp_init_tcp_state, lm_tcp_init_rx_con/tx_con already called
 *  - send unacked data already posted
 * Returns:
 *  SUCCESS or any failure */
lm_status_t lm_tcp_init_tcp_common(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_init_tcp_common\n");
    DbgBreakIf(!(pdev && tcp));

    lm_status = lm_tcp_init_tcp_state_machine(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    lm_status = lm_tcp_init_tcp_context(pdev, tcp);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        tcp->rx_con->u.rx.gen_info.dont_send_to_system_more_then_rwin = FALSE; //TRUE;
    }

    return LM_STATUS_SUCCESS;
}


static void _lm_tcp_comp_upload_neigh_request(
    struct _lm_device_t * pdev,
    lm_neigh_state_t    * neigh_state)
{
    DbgBreakIf(neigh_state->hdr.status != STATE_STATUS_UPLOAD_PENDING);
    DbgBreakIf(neigh_state->hdr.state_id != STATE_ID_NEIGH);

    DbgBreakIf(neigh_state->num_dependents);

    neigh_state->hdr.status = STATE_STATUS_UPLOAD_DONE;
    mm_tcp_complete_neigh_upload_request(pdev, neigh_state);
}


/** Description
 *  upload path state
 * Assumptions:
 *   called under TOE-lock
 */
static void _lm_tcp_comp_upload_path_request(
    struct _lm_device_t * pdev,
    lm_path_state_t     * path_state)
{
    lm_neigh_state_t * neigh = NULL;

    DbgBreakIf(path_state->hdr.status != STATE_STATUS_UPLOAD_PENDING);
    DbgBreakIf(path_state->hdr.state_id != STATE_ID_PATH);

    path_state->hdr.status = STATE_STATUS_UPLOAD_DONE;

    DbgBreakIf(path_state->neigh->num_dependents == 0);
    path_state->neigh->num_dependents--;
    if ((path_state->neigh->num_dependents == 0) &&
        (path_state->neigh->hdr.status == STATE_STATUS_UPLOAD_PENDING)) {
        /* Time to release the neighbor resources...*/
        neigh = path_state->neigh;
    }
    path_state->neigh = NULL;

    DbgBreakIf(path_state->num_dependents);

    mm_tcp_complete_path_upload_request(pdev, path_state);

    if (neigh) {
        _lm_tcp_comp_upload_neigh_request(pdev, neigh);
    }
}


/* post initiate offload slow path ramrod
 * returns SUCCESS or any failure */
static lm_status_t lm_tcp_post_initiate_offload_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    u8_t *command,
    u64_t *data)
{
    lm_tcp_con_t *con = tcp->tx_con;
    int           i   = 0;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_post_initiate_offload_request\n");
    DbgBreakIf(tcp->hdr.status != STATE_STATUS_INIT_CONTEXT);
    tcp->hdr.status = STATE_STATUS_OFFLOAD_PENDING;

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        con = tcp->tx_con;
        for (i = 0; i < 2; i++) {
            mm_acquire_tcp_lock(pdev, con);
            DbgBreakIf(!(con->flags & TCP_POST_BLOCKED));
            DbgBreakIf(!(con->flags & TCP_COMP_BLOCKED));
            con->flags &= ~TCP_COMP_BLOCKED;
            con->flags |= TCP_COMP_DEFERRED; /* completions are now allowed but deferred */
            mm_release_tcp_lock(pdev, con);
            con = tcp->rx_con;
        }
    }

    tcp->sp_flags |= SP_TCP_OFLD_REQ_POSTED;
    *command = (tcp->ulp_type == TOE_CONNECTION_TYPE)? RAMROD_OPCODE_TOE_INITIATE_OFFLOAD : L5CM_RAMROD_CMD_ID_ADD_NEW_CONNECTION;
    *data = tcp->ctx_phys.as_u64;

    return LM_STATUS_PENDING;
}


static lm_status_t lm_tcp_post_terminate_tcp_request (
    IN    struct _lm_device_t   * pdev,
    IN    lm_tcp_state_t        * tcp,
    OUT   u8_t                  * command,
    OUT   u64_t                 * data
    )
{
    DbgMessage(pdev, VERBOSEl4sp, "## lm_tcp_post_terminate_tcp_request\n");

    DbgBreakIf(tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING);

    lm_tcp_flush_db(pdev,tcp);

    SET_FLAGS(tcp->sp_flags, SP_TCP_TRM_REQ_POSTED );

    *command = (tcp->ulp_type == TOE_CONNECTION_TYPE)? RAMROD_OPCODE_TOE_TERMINATE : L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD;
    *data = 0;

    return LM_STATUS_PENDING;
}

/**
 Description:
 *  Posts RST request.
 *
 * Assumptions:
 *  - Global TOE lock is already taken by the caller.
 *
 * Returns:
 *  SUCCESS or any failure
 *
 */
static lm_status_t lm_tcp_post_abortive_disconnect_request (
    IN    struct _lm_device_t   * pdev,
    IN    lm_tcp_state_t        * tcp,
    OUT   u8_t                  * command,
    OUT   u64_t                 * data
    )
{
    /* Get Rx and Tx connections */
    lm_tcp_con_t *rx_con = tcp->rx_con;
    lm_tcp_con_t *tx_con = tcp->tx_con;

    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4sp, "## lm_tcp_post_abortive_disconnect_request\n");
    DbgBreakIf( (tcp->hdr.status != STATE_STATUS_NORMAL ) &&
                (tcp->hdr.status != STATE_STATUS_ABORTED) );

/*********************** Tx **********************/
    /* Take Tx lock */
    mm_acquire_tcp_lock(pdev, tx_con);

    /* This will imply Tx POST_BLOCKED */
    tx_con->flags |= TCP_RST_REQ_POSTED;

    /* Release Tx lock */
    mm_release_tcp_lock(pdev, tx_con);

/*********************** Rx **********************/
    /* Take Rx lock */
    mm_acquire_tcp_lock(pdev, rx_con);

    /* This will imply Rx POST_BLOCKED and IND_BLOCKED */
    rx_con->flags |= TCP_RST_REQ_POSTED;

    /* Release Rx lock */
    mm_release_tcp_lock(pdev, rx_con);
/**************Post the ramrod *******************/
    *command = RAMROD_OPCODE_TOE_RESET_SEND;
    *data = 0;

    return LM_STATUS_PENDING;
}


/**
 Description:
 *  Initiates the TCP connection upload process.
 *  Posts a Searcher ramrod to the chip.
 *
 * Assumptions:
 *  - Global TOE lock is already taken by the caller.
 *  - UM caller has allocated "struct toe_context" phys. cont. buffer
 *    and put its address to "data.phys_addr".
 * Returns:
 *  SUCCESS or any failure
 *
 */
static lm_status_t lm_tcp_post_upload_tcp_request (
    IN    struct _lm_device_t   * pdev,
    IN    lm_tcp_state_t        * tcp,
    OUT   u8_t                  * command,
    OUT   u64_t                 * data
    )
{
    lm_tcp_con_t *rx_con, *tx_con = NULL;
    struct toe_spe         spe    = {{0}};
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4sp, "## lm_tcp_post_upload_tcp_request\n");
    DbgBreakIf(tcp->hdr.status < STATE_STATUS_NORMAL);
    DbgBreakIf(tcp->hdr.status >= STATE_STATUS_UPLOAD_PENDING);
    DbgBreakIf(tcp->hdr.state_id != STATE_ID_TCP);


    /* Set the status of the connection to UPLOAD_PENDING */
    tcp->hdr.status = STATE_STATUS_UPLOAD_PENDING;

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        /* Get Rx and Tx connections */
        rx_con = tcp->rx_con;
        tx_con = tcp->tx_con;

        /* Set the flags for the connections (Rx and Tx) */
        /* Tx */
        mm_acquire_tcp_lock(pdev, tx_con);
        DbgBreakIf(tx_con->flags & TCP_TRM_REQ_POSTED);
        tx_con->flags |= TCP_TRM_REQ_POSTED;
        mm_release_tcp_lock(pdev, tx_con);
        /* Rx */
        mm_acquire_tcp_lock(pdev, rx_con);
        DbgBreakIf(rx_con->flags & TCP_TRM_REQ_POSTED);
        rx_con->flags |= TCP_TRM_REQ_POSTED;
        mm_release_tcp_lock(pdev, rx_con);
    }

    tcp->sp_flags |= SP_TCP_SRC_REQ_POSTED;

    *command = (tcp->ulp_type == TOE_CONNECTION_TYPE)? RAMROD_OPCODE_TOE_SEARCHER_DELETE : L5CM_RAMROD_CMD_ID_SEARCHER_DELETE;
    spe.toe_data.rx_completion.hash_value = (u16_t)(tcp->tcp_const.hash_value);
    *data = *((u64_t*)(&(spe.toe_data.rx_completion)));

    return LM_STATUS_PENDING;
}

static lm_status_t lm_tcp_post_query_request (
    IN    struct _lm_device_t        * pdev,
    IN    lm_tcp_state_t             * tcp,
    OUT   u8_t                       * command,
    OUT   u64_t                      * data,
    IN    lm_tcp_slow_path_request_t * request
    )
{
    struct toe_spe spe = {{0}};

    UNREFERENCED_PARAMETER_(request);

    DbgMessage(pdev, VERBOSEl4sp, "## lm_tcp_post_query_request\n");

    tcp->sp_flags |= SP_TCP_QRY_REQ_POSTED;
    *command = (tcp->ulp_type == TOE_CONNECTION_TYPE)? RAMROD_OPCODE_TOE_QUERY : L5CM_RAMROD_CMD_ID_QUERY;

    mm_memset(tcp->sp_req_data.virt_addr, 0, TOE_SP_PHYS_DATA_SIZE);

    spe.toe_data.phys_addr.hi = tcp->sp_req_data.phys_addr.as_u32.high;
    spe.toe_data.phys_addr.lo = tcp->sp_req_data.phys_addr.as_u32.low;
    *data = *((u64_t*)(&(spe.toe_data.phys_addr)));

    return LM_STATUS_PENDING;
}

lm_status_t lm_tcp_post_upload_path_request (
    struct _lm_device_t * pdev,
    lm_path_state_t * path_state,
    l4_path_delegated_state_t * ret_delegated)
{

    DbgBreakIf(path_state->hdr.status != STATE_STATUS_NORMAL);
    DbgBreakIf(path_state->hdr.state_id != STATE_ID_PATH);

    /* MichalS TBA: do we need this? (also in spec ('ipv4_current_ip_id' unclear)) */
    *ret_delegated = path_state->path_delegated;

    DbgMessage(pdev, INFORMl4sp, "lm_tcp_post_upload_path_request: num_dependents=%d\n", path_state->num_dependents);

    if (path_state->num_dependents == 0) {
        path_state->hdr.status = STATE_STATUS_UPLOAD_DONE;
        return LM_STATUS_SUCCESS;
    }
    path_state->hdr.status = STATE_STATUS_UPLOAD_PENDING;
    return LM_STATUS_PENDING;

}

lm_status_t lm_tcp_post_upload_neigh_request(
    struct _lm_device_t * pdev,
    lm_neigh_state_t * neigh_state
    )
{
    DbgBreakIf(neigh_state->hdr.status != STATE_STATUS_NORMAL);
    DbgBreakIf(neigh_state->hdr.state_id != STATE_ID_NEIGH);

    DbgMessage(pdev, INFORMl4sp, "lm_tcp_post_upload_neigh_request: num_dependents=%d\n", neigh_state->num_dependents);

    #if DBG
    {
        /* NirV: multi client todo */
        lm_path_state_t * path = (lm_path_state_t *) d_list_peek_head(&pdev->toe_info.state_blk.path_list);
        while(path) {
            if(path->neigh == neigh_state) {
                DbgBreakIf(path->hdr.status == STATE_STATUS_NORMAL);
            }
            path = (lm_path_state_t *) d_list_next_entry(&path->hdr.link);
        }
    }
    #endif

    if (neigh_state->num_dependents == 0) {
        neigh_state->hdr.status = STATE_STATUS_UPLOAD_DONE;
        return LM_STATUS_SUCCESS;
    }
    neigh_state->hdr.status = STATE_STATUS_UPLOAD_PENDING;
    return LM_STATUS_PENDING;

}

/* sets the cached parameters of tcp/path/neigh and initializes a toe_context (which is initially all zeros) */
static lm_status_t lm_tcp_set_tcp_cached(
    struct _lm_device_t     * pdev,
    lm_tcp_state_t          * tcp,
    l4_tcp_cached_state_t   * tcp_cached,
    void                    * mem_virt        /* firmware context */
    )
{
    struct toe_update_ramrod_cached_params * ctx       = mem_virt;
    l4_ofld_params_t                       * l4_params = &(pdev->ofld_info.l4_params);

    MM_INIT_TCP_LOCK_HANDLE();

    /* tcp-flags */
    DbgMessage(pdev, INFORMl4sp, "## lm_tcp_set_tcp_cached cid=%d\n", tcp->cid);

    if ((tcp->tcp_cached.tcp_flags & TCP_FLAG_ENABLE_KEEP_ALIVE) !=
        (tcp_cached->tcp_flags & TCP_FLAG_ENABLE_KEEP_ALIVE)) {
        if (tcp_cached->tcp_flags & TCP_FLAG_ENABLE_KEEP_ALIVE) {
            ctx->enable_keepalive = 1;
        } else {
            ctx->enable_keepalive = 0;
        }
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_ENABLE_KEEPALIVE_CHANGED;
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached: [cid=%d] update : flag TCP_FLAG_ENABLE_KEEP_ALIVE changed to %d\n",
                    tcp->cid, ctx->enable_keepalive);
    }
    if ((tcp->tcp_cached.tcp_flags & TCP_FLAG_ENABLE_NAGLING) !=
        (tcp_cached->tcp_flags & TCP_FLAG_ENABLE_NAGLING)) {
        if (tcp_cached->tcp_flags & TCP_FLAG_ENABLE_NAGLING) {
            ctx->enable_nagle = 1;
        } else {
            ctx->enable_nagle = 0;
        }
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_ENABLE_NAGLE_CHANGED;
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : flag TCP_FLAG_ENABLE_NAGLING changed to %d\n",
                    tcp->cid, ctx->enable_nagle);
    }
    if (tcp_cached->tcp_flags & TCP_FLAG_RESTART_KEEP_ALIVE) {
        ctx->ka_restart = 1;
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : flag TCP_FLAG_RESTART_KEEP_ALIVE set\n",
                    tcp->cid);
    } else {
        ctx->ka_restart = 0;
    }
    if (tcp_cached->tcp_flags & TCP_FLAG_RESTART_MAX_RT) {
        ctx->retransmit_restart = 1;
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : flag TOE_CACHED_RESTART_MAX_RT set\n",
                    tcp->cid);
    } else {
        ctx->retransmit_restart = 0;
    }
    if (tcp_cached->tcp_flags & TCP_FLAG_UPDATE_RCV_WINDOW) {
        /* for debugging purposes */
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : flag TCP_FLAG_UPDATE_RCV_WINDOW set\n",
                    tcp->cid);
    }

    tcp->tcp_cached.tcp_flags = tcp_cached->tcp_flags;

    /* flow label ipv6 only */
    if (tcp->path->path_const.ip_version == IP_VERSION_IPV6) {
        if (tcp->tcp_cached.flow_label != tcp_cached->flow_label) {
            DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : flow_label changed from %d to %d\n",
                        tcp->cid, tcp->tcp_cached.flow_label, tcp_cached->flow_label);
            tcp->tcp_cached.flow_label = tcp_cached->flow_label;
            ctx->flow_label= tcp->tcp_cached.flow_label;
            ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_FLOW_LABEL_CHANGED;
        }
    }

    /* initial_rcv_wnd */
    if (tcp->tcp_cached.initial_rcv_wnd != tcp_cached->initial_rcv_wnd) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : initial_rcv_wnd changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.initial_rcv_wnd, tcp_cached->initial_rcv_wnd);
        /* no change to firmware */
        mm_tcp_update_required_gen_bufs(pdev,
                                        tcp->rx_con->u.rx.sws_info.mss,   /* new-mss(no change)*/
                                        tcp->rx_con->u.rx.sws_info.mss,   /* old-mss*/
                                        tcp_cached->initial_rcv_wnd,      /* new initial receive window */
                                        tcp->tcp_cached.initial_rcv_wnd); /* old initial receive window */

        /* In VISTA and higher, window CAN decrease! */
        if ERR_IF(tcp_cached->initial_rcv_wnd > MAX_INITIAL_RCV_WND) {
            /* TBD: Miniport doesn't handle any parameter other than SUCCESS / PENDING... */
            /* TODO: return LM_STATUS_INVALID_PARAMETER; */
            DbgBreakIfAll(tcp_cached->initial_rcv_wnd > MAX_INITIAL_RCV_WND);
        }
        /* update the sws_bytea accordingly */
        mm_acquire_tcp_lock(pdev,tcp->rx_con);
        /* it's now time to give the window doorbell in-case there was a window update - could be negative, in which case, special handling is required... */
        if (tcp->tcp_cached.initial_rcv_wnd < tcp_cached->initial_rcv_wnd) {
            /* regular window update */
            lm_tcp_rx_post_sws(pdev, tcp, tcp->rx_con, tcp_cached->initial_rcv_wnd - tcp->tcp_cached.initial_rcv_wnd, TCP_RX_POST_SWS_INC);
        } else {
            lm_tcp_rx_post_sws(pdev, tcp, tcp->rx_con, tcp->tcp_cached.initial_rcv_wnd - tcp_cached->initial_rcv_wnd, TCP_RX_POST_SWS_DEC);
            pdev->toe_info.toe_events |= LM_TOE_EVENT_WINDOW_DECREASE;
        }
        mm_release_tcp_lock(pdev, tcp->rx_con);
        tcp->tcp_cached.initial_rcv_wnd = tcp_cached->initial_rcv_wnd;
        ctx->initial_rcv_wnd = tcp->tcp_cached.initial_rcv_wnd;
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_INITIAL_RCV_WND_CHANGED;
    }

    /*ttl_or_hop_limit*/
    if (tcp->tcp_cached.ttl_or_hop_limit != tcp_cached->ttl_or_hop_limit) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : ttl_or_hop_limit changed from %d to %d\n",
                        tcp->cid, tcp->tcp_cached.ttl_or_hop_limit, tcp_cached->ttl_or_hop_limit);
        tcp->tcp_cached.ttl_or_hop_limit = tcp_cached->ttl_or_hop_limit;
        if (tcp->path->path_const.ip_version == IP_VERSION_IPV4) {
            ctx->ttl= tcp->tcp_cached.ttl_or_hop_limit;
            ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_TTL_CHANGED;
        } else {
            ctx->hop_limit = tcp->tcp_cached.ttl_or_hop_limit;
            ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_HOP_LIMIT_CHANGED;
        }
    }

    /* tos_or_traffic_class */
    if (tcp->tcp_cached.tos_or_traffic_class != tcp_cached->tos_or_traffic_class) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : tos_or_traffic_class changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.tos_or_traffic_class, tcp_cached->tos_or_traffic_class);
        tcp->tcp_cached.tos_or_traffic_class = tcp_cached->tos_or_traffic_class;

        if (tcp->path->path_const.ip_version == IP_VERSION_IPV4) {
            ctx->tos = tcp_cached->tos_or_traffic_class;
            ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_TOS_CHANGED;
        } else {
            ctx->traffic_class = tcp_cached->tos_or_traffic_class;
            ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_TRAFFIC_CLASS_CHANGED;
        }
    }

    /* ka_probe_cnt */
    if (tcp->tcp_cached.ka_probe_cnt != tcp_cached->ka_probe_cnt) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : ka_probe_cnt changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.ka_probe_cnt, tcp_cached->ka_probe_cnt);
        tcp->tcp_cached.ka_probe_cnt = tcp_cached->ka_probe_cnt;
        ctx->ka_max_probe_count = tcp_cached->ka_probe_cnt;
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_KA_MAX_PROBE_COUNT_CHANGED;
    }

    /* user_priority */
    if (tcp->tcp_cached.user_priority != tcp_cached->user_priority) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : user_priority changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.user_priority, tcp_cached->user_priority);
        DbgBreakIf(tcp_cached->user_priority > 0x7);
        tcp->tcp_cached.user_priority = tcp_cached->user_priority;
        ctx->user_priority = tcp_cached->user_priority;
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_USER_PRIORITY_CHANGED;
    }

    /* rcv_indication_size */
    DbgBreakIf(tcp_cached->rcv_indication_size != 0);
    if (tcp->tcp_cached.rcv_indication_size != tcp_cached->rcv_indication_size) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : rcv_indication_size changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.rcv_indication_size, tcp_cached->rcv_indication_size);
        DbgBreakIf(tcp->tcp_cached.rcv_indication_size > 0xffff);
        tcp->tcp_cached.rcv_indication_size = tcp_cached->rcv_indication_size;
        ctx->rcv_indication_size = (u16_t)tcp_cached->rcv_indication_size;
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_RCV_INDICATION_SIZE_CHANGED;
    }

    /* ka_time_out */
    if (tcp->tcp_cached.ka_time_out != tcp_cached->ka_time_out) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : ka_time_out changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.ka_time_out, tcp_cached->ka_time_out);
        tcp->tcp_cached.ka_time_out = tcp_cached->ka_time_out;
        ctx->ka_timeout =
            lm_time_resolution(pdev, tcp->tcp_cached.ka_time_out, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC);
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_KA_TIMEOUT_CHANGED;
    }

    /* ka_interval */
    if (tcp->tcp_cached.ka_interval != tcp_cached->ka_interval) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : ka_interval changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.ka_interval, tcp_cached->ka_interval);
        tcp->tcp_cached.ka_interval = tcp_cached->ka_interval;
        ctx->ka_interval =
            lm_time_resolution(pdev, tcp->tcp_cached.ka_interval, l4_params->ticks_per_second, TIMERS_TICKS_PER_SEC);
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_KA_INTERVAL_CHANGED;
    }

    /* max_rt */
    if (tcp->tcp_cached.max_rt != tcp_cached->max_rt) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : max_rt changed from %d to %d\n",
                    tcp->cid, tcp->tcp_cached.max_rt, tcp_cached->max_rt);
        tcp->tcp_cached.max_rt = tcp_cached->max_rt;
        ctx->max_rt =
            lm_time_resolution(pdev, tcp->tcp_cached.max_rt, l4_params->ticks_per_second, TSEMI_CLK1_TICKS_PER_SEC);
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_MAX_RT_CHANGED;
    }

    if (!ctx->changed_fields && !ctx->ka_restart && !ctx->retransmit_restart) {
        DbgMessage(pdev, INFORMl4sp, "## tcp_cached [cid=%d] update : nothing changed,  completing synchronously\n", tcp->cid);
        return LM_STATUS_SUCCESS; /* synchronous complete */
    }
    //DbgMessage(pdev, WARNl4sp, "## lm_tcp_set_tcp_cached cid=%d DONE!\n", tcp->cid);
    return LM_STATUS_PENDING;
}

/* sets the cached parameters of tcp/path/neigh and initializes a toe_context (which is initially all zeros) */
static lm_status_t lm_tcp_set_path_cached(
    struct _lm_device_t     * pdev,
    lm_tcp_state_t          * tcp,
    l4_path_cached_state_t  * path_cached,
    void                    * mem_virt        /* firmware context */
    )
{
    struct toe_update_ramrod_cached_params * ctx    = mem_virt;
    u32_t                                   new_mss = 0;

    new_mss = _lm_tcp_calc_mss(path_cached->path_mtu,
                               tcp->tcp_const.remote_mss,
                               (tcp->path->path_const.ip_version == IP_VERSION_IPV6),
                               tcp->tcp_const.tcp_flags & TCP_FLAG_ENABLE_TIME_STAMP,
                               pdev->ofld_info.l4_params.flags & OFLD_PARAM_FLAG_SNAP_ENCAP,
                               tcp->path->neigh->neigh_const.vlan_tag  != 0);

    if (new_mss != tcp->rx_con->u.rx.sws_info.mss) {
        /* also need to notify um, since this may affect the number of generic buffers
         * required. */
        DbgMessage(pdev, INFORMl4sp, "## path_cached: tcp [cid=%d] update : mss (as a result of pathMtu) from %d to %d\n",
                    tcp->cid, tcp->rx_con->u.rx.sws_info.mss, new_mss);
        mm_tcp_update_required_gen_bufs(pdev,
                                        new_mss,
                                        tcp->rx_con->u.rx.sws_info.mss,   /* old-mss*/
                                        tcp->tcp_cached.initial_rcv_wnd,  /* new initial receive window */
                                        tcp->tcp_cached.initial_rcv_wnd); /* old initial receive window */

        tcp->rx_con->u.rx.sws_info.mss = new_mss;
        DbgBreakIf(new_mss > 0xffff);
        ctx->mss = (u16_t)new_mss;
        ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_MSS_CHANGED;
    }

    if (ctx->changed_fields == 0) {
        return LM_STATUS_SUCCESS; /* synchronous complete */
    }

    return LM_STATUS_PENDING;
}

/* sets the cached parameters of tcp/path/neigh and initializes a toe_context (which is initially all zeros)
 * Assumption: this function is only called if in-fact, the destination address changed.
 */
static lm_status_t lm_tcp_set_neigh_cached(
    struct _lm_device_t     * pdev,
    lm_tcp_state_t          * tcp,
    l4_neigh_cached_state_t * neigh_cached,
    void                    * mem_virt        /* firmware context */
    )
{
    struct toe_update_ramrod_cached_params * ctx = mem_virt;
    int    i                                     = 0;

    DbgMessage(pdev, INFORMl4sp, "## neigh_cached: tcp [cid=%d] update : neighbor dst_addr\n", tcp->cid);

    for (i = 0; i < 6; i++) {
        ctx->dest_addr[i] = (u8_t)neigh_cached->dst_addr[i]; /* TBA Michals : is this init correct? order of assignment*/
    }
    ctx->changed_fields |= TOE_UPDATE_RAMROD_CACHED_PARAMS_DEST_ADDR_CHANGED;

    return LM_STATUS_PENDING;
}

static lm_status_t lm_tcp_post_update_request (
    IN    struct _lm_device_t        * pdev,
    IN    lm_tcp_state_t             * tcp,
    OUT   u8_t                       * command,
    OUT   u64_t                      * data,
    IN    lm_tcp_slow_path_request_t * request
    )
{
    struct toe_spe spe       = {{0}};
    lm_status_t    lm_status = LM_STATUS_FAILURE ;

    DbgBreakIf(tcp->hdr.state_id != STATE_ID_TCP);

    *command = RAMROD_OPCODE_TOE_UPDATE;
    spe.toe_data.phys_addr.hi = tcp->sp_req_data.phys_addr.as_u32.high;
    spe.toe_data.phys_addr.lo = tcp->sp_req_data.phys_addr.as_u32.low;
    *data = *((u64_t*)(&(spe.toe_data.phys_addr)));
    mm_memset(tcp->sp_req_data.virt_addr, 0, sizeof(struct toe_update_ramrod_cached_params));

    DbgBreakIf((tcp->hdr.status != STATE_STATUS_NORMAL) &&
               (tcp->hdr.status != STATE_STATUS_ABORTED));

    /* we need to initialize the data for firmware */
    switch(request->type) {
    case SP_REQUEST_UPDATE_TCP:
        lm_status = lm_tcp_set_tcp_cached(pdev, tcp,
                                          request->sent_data.tcp_update_data.data,
                                          tcp->sp_req_data.virt_addr);
        break;
    case SP_REQUEST_UPDATE_PATH:
        DbgBreakIf(tcp->path->hdr.status != STATE_STATUS_NORMAL);
        DbgBreakIf(tcp->path->neigh->hdr.status != STATE_STATUS_NORMAL);
        lm_status = lm_tcp_set_path_cached(pdev, tcp,
                                           request->sent_data.tcp_update_data.data,
                                           tcp->sp_req_data.virt_addr);
        break;
    case SP_REQUEST_UPDATE_NEIGH:
        DbgBreakIf(tcp->path->neigh->hdr.status != STATE_STATUS_NORMAL);

        lm_status = lm_tcp_set_neigh_cached(pdev, tcp,
                                            request->sent_data.tcp_update_data.data,
                                            tcp->sp_req_data.virt_addr);
        break;
    case SP_REQUEST_UPDATE_PATH_RELINK:
        /* we will always return PENDING status */
        DbgBreakIf(tcp->path->neigh->hdr.status != STATE_STATUS_NORMAL);
        lm_status = lm_tcp_set_neigh_cached(pdev, tcp,
                                            &((lm_tcp_path_relink_cached_t *)request->sent_data.tcp_update_data.data)->neigh_cached,
                                            tcp->sp_req_data.virt_addr);

        DbgBreakIf(tcp->path->hdr.status != STATE_STATUS_NORMAL);
        DbgBreakIf(tcp->path->neigh->hdr.status != STATE_STATUS_NORMAL);
        lm_tcp_set_path_cached(pdev, tcp, &((lm_tcp_path_relink_cached_t *)request->sent_data.tcp_update_data.data)->path_cached,
                                           tcp->sp_req_data.virt_addr);
        break;
    }

    return lm_status;
}

static lm_status_t lm_tcp_post_empty_ramrod_request(
    IN struct _lm_device_t         * pdev,
    IN lm_tcp_state_t              * tcp,
    OUT u8_t                       * command,
    OUT u64_t                      * data)
{
    struct toe_spe spe = {{0}};

    DbgMessage(pdev, VERBOSEl4sp, "## lm_tcp_post_empty_ramrod_request\n");

    *command = RAMROD_OPCODE_TOE_EMPTY_RAMROD;
    spe.toe_data.rx_completion.hash_value = (u16_t)(tcp->tcp_const.hash_value);
    *data = *((u64_t*)(&(spe.toe_data.rx_completion)));

    return LM_STATUS_PENDING;
}

static lm_status_t lm_tcp_post_invalidate_request(
    IN struct _lm_device_t         * pdev,
    IN lm_tcp_state_t              * tcp,
    OUT u8_t                       * command,
    OUT u64_t                      * data)
{
    /* Get Rx and Tx connections */
    lm_tcp_con_t * rx_con = tcp->rx_con;
    lm_tcp_con_t * tx_con = tcp->tx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4sp, "## lm_tcp_post_invalidate_request cid=%d\n", tcp->cid);

    DbgBreakIf(tcp->hdr.status != STATE_STATUS_NORMAL &&
               tcp->hdr.status != STATE_STATUS_ABORTED);

    /* Set the flags for the connections (Rx and Tx) */
    /* Tx */
    mm_acquire_tcp_lock(pdev, tx_con);
    DbgBreakIf(tx_con->flags & TCP_INV_REQ_POSTED);
    tx_con->flags |= TCP_INV_REQ_POSTED;
    mm_release_tcp_lock(pdev, tx_con);
    /* Rx */
    mm_acquire_tcp_lock(pdev, rx_con);
    DbgBreakIf(rx_con->flags & TCP_INV_REQ_POSTED);
    rx_con->flags |= TCP_INV_REQ_POSTED;
    mm_release_tcp_lock(pdev, rx_con);


    *command = RAMROD_OPCODE_TOE_INVALIDATE;
    *data = 0;

    return LM_STATUS_PENDING;
}


/* Desciption:
 *  post slow path request of given type for given tcp state
 * Assumptions:
 *  - caller initialized request->type according to his specific request
 *  - caller allocated space for request->data, according to the specific request type
 *  - all previous slow path requests for given tcp state are already completed
 * Returns:
 *  PENDING, SUCCESS or any failure */
lm_status_t lm_tcp_post_slow_path_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_slow_path_request_t *request)
{
    lm_status_t lm_status = LM_STATUS_INVALID_PARAMETER;
    u64_t       data      = 0;
    u8_t        command   = 0;

    DbgBreakIf(!(pdev && tcp && request));
    DbgBreakIf(tcp->sp_request); /* lm supports only one pending slow path request per connection */
    DbgMessage(pdev, VERBOSEl4sp, "### lm_tcp_post_slow_path_request cid=%d, type=%d\n", tcp->cid, request->type);
    DbgBreakIf(tcp->cid && (tcp != lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, tcp->cid)));
    tcp->sp_request = request;

    switch(request->type) {
    /* call the type specific post function that:
    execute any actions required for the specific sp request (possibly take tx/rx locks for that)
    according to state, possibly set the request status and complete the request synchronously
    fill the appropriate content in the lm information structure of the request */
    case SP_REQUEST_INITIATE_OFFLOAD:
        lm_status = lm_tcp_post_initiate_offload_request(pdev, tcp, &command, &data);
        break;
    case SP_REQUEST_TERMINATE1_OFFLOAD:
        lm_status = lm_tcp_post_terminate_tcp_request(pdev, tcp, &command, &data);
        break;
    case SP_REQUEST_TERMINATE_OFFLOAD:
        lm_status = lm_tcp_post_upload_tcp_request(pdev, tcp, &command, &data);
        break;
    case SP_REQUEST_QUERY:
        lm_status = lm_tcp_post_query_request(pdev, tcp, &command, &data, request);
        break;
    case SP_REQUEST_UPDATE_TCP:
    case SP_REQUEST_UPDATE_PATH:
    case SP_REQUEST_UPDATE_NEIGH:
    case SP_REQUEST_UPDATE_PATH_RELINK:
        lm_status = lm_tcp_post_update_request(pdev, tcp, &command, &data, request);
        break;
    case SP_REQUEST_INVALIDATE:
        lm_status = lm_tcp_post_invalidate_request(pdev, tcp, &command, &data);
        break;
    case SP_REQUEST_ABORTIVE_DISCONNECT:
        lm_status = lm_tcp_post_abortive_disconnect_request(pdev,tcp, &command, &data);
        break;
    case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
    case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
    case SP_REQUEST_PENDING_TX_RST:
        lm_status = lm_tcp_post_empty_ramrod_request(pdev, tcp, &command, &data);
        break;
    default:
        DbgBreakMsg("Illegal slow path request type!\n");
    }
    if(lm_status == LM_STATUS_PENDING) {
        DbgMessage(pdev, VERBOSEl4sp,
                   "calling lm_command_post, cid=%d, command=%d, con_type=%d, data=%lx\n",
                   tcp->cid, command, tcp->ulp_type, data);
        if (tcp->hdr.status == STATE_STATUS_UPLOAD_DONE)
        {
            /* no slow path request can be posted after connection is uploaded */
            DbgBreakIf(tcp->hdr.status == STATE_STATUS_UPLOAD_DONE);
            tcp->sp_request = NULL;
            lm_status = LM_STATUS_INVALID_PARAMETER;
        } else
        {
            lm_command_post(pdev, tcp->cid, command, CMD_PRIORITY_NORMAL, tcp->ulp_type, data);
        }
    } else {
        tcp->sp_request = NULL;
    }

    request->status = lm_status;
    return lm_status;
}

/* slow path request completion template */
// lm_status_t lm_tcp_comp_XXX_slow_path_request(struct _lm_device_t *pdev,
//                                               lm_tcp_state_t *tcp,
//                                               ...cqe...)
// {
//     lm_tcp_slow_path_request_t *sp_request;
//
//     DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_comp_XXX_slow_path_request\n");
//     MM_ACQUIRE_TOE_LOCK(pdev);
//     DbgBreakIf(tcp->hdr.status != STATE_STATUS_YYY);
//     tcp->hdr.status = STATE_STATUS_ZZZ;
//     execute lm state actions if required
//     lm_sp_ring_command_completed (*) [not here, automatically in 'process CQ']
//     MM_RELEASE_TOE_LOCK(pdev);
//     under tx lock, execute any Tx actions required (possibly call mm_*)
//     under rx lock, execute any Rx actions required (possibly call mm_*)
//     MM_ACQUIRE_TOE_LOCK(pdev);
//     tcp->sp_flags ~= (SP_REQ_COMPLETED_RX | SP_REQ_COMPLETED_TX)
//     tcp->sp_request->status = completion status;
//     sp_request = tcp->sp_request;
//     tcp->sp_request = NULL
//     mm_tcp_comp_slow_path_request(tcp, sp_request)
//     MM_RELEASE_TOE_LOCK(pdev);
// }
void lm_tcp_service_deferred_cqes(lm_device_t * pdev, lm_tcp_state_t * tcp)
{
    lm_tcp_con_t * con         = tcp->tx_con;
    u8_t           idx = 0, dead=FALSE;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4sp, "### lm_tcp_service_deferred_cqes cid=%d\n", tcp->cid);



    for (idx = 0; idx < 2; idx++) {
        mm_acquire_tcp_lock(pdev, con);
        while(con->flags & TCP_DEFERRED_PROCESSING) {
            /* consistent state. at this stage, since we have the lock and deferred cqes need the lock
             * for processing, it's as if we have just processed X cqes and are about to complete the fp
             * of these cqes... During the complete of fp and sp, the lock may be released, in this case
             * more cqes may be processed, in which case TCP_DEFERRED_PROCESSING will be switched back on. */
            con->flags &= ~TCP_DEFERRED_PROCESSING;
            DbgMessage(pdev, INFORMl4sp, "### deferred cid=%d\n", tcp->cid);

            if (con->type == TCP_CON_TYPE_RX) {
                lm_tcp_rx_complete_tcp_fp(pdev, con->tcp_state, con);
            } else {
                lm_tcp_tx_complete_tcp_fp(pdev, con->tcp_state, con);
            }

            if (con->dpc_info.snapshot_flags) {
                mm_release_tcp_lock(pdev, con);

                if (con->type == TCP_CON_TYPE_RX) {
                    lm_tcp_rx_complete_tcp_sp(pdev,tcp, con);
                } else {
                    lm_tcp_tx_complete_tcp_sp(pdev,tcp, con);
                }

                mm_acquire_tcp_lock(pdev, con);
            }
        }

        con->flags &= ~TCP_COMP_DEFERRED; /* completions are no longer deferred */

        /* it's possible, that while processing the deferred cqes - the connection was uploaded,
         *  since the TCP_COMP_DEFERRED flag was still on - we didn't delete it yet, now is the time
         * to delete it... note, that this can only happen while we're handling the deferred cqes of
         * Rx_con - since query will only complete on RX and not TX, that's why it's safe to check and
         * after handling rx we won't access this connection anymore....*/
        dead = lm_tcp_is_tcp_dead(pdev, tcp, TCP_IS_DEAD_OP_OFLD_COMP_DFRD);


        mm_release_tcp_lock(pdev, con);

        con = tcp->rx_con;

        if (dead) {
            mm_tcp_del_tcp_state(pdev, tcp);
        }

    }
}

/* initiate offload request completion */
void lm_tcp_comp_initiate_offload_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    u32_t comp_status)
{
    lm_tcp_slow_path_request_t *sp_request;
    lm_tcp_con_t *con;
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    int i;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4sp, "##lm_tcp_comp_initiate_offload_request\n");

    MM_ACQUIRE_TOE_LOCK(pdev);

    DbgBreakIf(tcp->hdr.status != STATE_STATUS_OFFLOAD_PENDING);

    if(!comp_status)
    { /* successful completion */
        tcp->hdr.status = STATE_STATUS_NORMAL;

        if (tcp->ulp_type == TOE_CONNECTION_TYPE)
        {
            con = tcp->tx_con;
            for (i = 0; i < 2; i++)
            {
                mm_acquire_tcp_lock(pdev, con);
                DbgBreakIf(!(con->flags & TCP_COMP_DEFERRED));
                DbgBreakIf(!(con->flags & TCP_POST_BLOCKED));
                con->flags &= ~TCP_POST_BLOCKED; /* posting is now allowed */
                mm_release_tcp_lock(pdev, con);
                con = tcp->rx_con;
            }

            // update stats counters if TOE
            if( IP_VERSION_IPV4 == tcp->path->path_const.ip_version )
            {
                ++pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[STATS_IP_4_IDX].currently_established;
            }
            else if( IP_VERSION_IPV6 == tcp->path->path_const.ip_version )
            {
                ++pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[STATS_IP_6_IDX].currently_established;
            }
        }
    }
    else
    {
#ifndef _VBD_CMD_
        DbgMessage(pdev, FATAL, "initiate offload failed. err=%x\n", comp_status);
#endif // _VBD_CMD_
        tcp->hdr.status = STATE_STATUS_INIT_OFFLOAD_ERR;

        if (tcp->ulp_type == TOE_CONNECTION_TYPE)
        {
            con = tcp->tx_con;
            for (i = 0; i < 2; i++)
            {
                mm_acquire_tcp_lock(pdev, con);
                DbgBreakIf((con->flags & ~TCP_INDICATE_REJECTED) != (TCP_POST_BLOCKED | TCP_COMP_DEFERRED));
                con->flags &= ~TCP_COMP_DEFERRED;
                con->flags |= TCP_COMP_BLOCKED; /* completions are blocked */
                mm_release_tcp_lock(pdev, con);
                con = tcp->rx_con;
            }
        }

        lm_status = LM_STATUS_FAILURE;
    }

    DbgBreakIf(tcp->sp_flags & (SP_REQUEST_COMPLETED_RX | SP_REQUEST_COMPLETED_TX));
    tcp->sp_request->status = lm_status;
//    DbgMessage(pdev, FATAL, "#lm_tcp_comp_initiate_offload_request cid=%d, sp_request->status=%d\n", tcp->cid, tcp->sp_request->status);
    sp_request = tcp->sp_request;
    tcp->sp_request = NULL;

    DbgBreakIf(!(tcp->sp_flags & SP_TCP_OFLD_REQ_POSTED));
    tcp->sp_flags |= SP_TCP_OFLD_REQ_COMP;
    mm_tcp_comp_slow_path_request(pdev, tcp, sp_request);

    MM_RELEASE_TOE_LOCK(pdev);

    /* handle deferred CQEs */
    if(!comp_status && (tcp->ulp_type == TOE_CONNECTION_TYPE)) {
        lm_tcp_service_deferred_cqes(pdev, tcp);
    }
}

void lm_tcp_collect_stats(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{

    if (tcp->tx_con && tcp->rx_con) {
        pdev->toe_info.stats.tx_bytes_posted_total += tcp->tx_con->bytes_post_cnt;
        pdev->toe_info.stats.tx_rq_complete_calls += tcp->tx_con->rq_completion_calls;
        pdev->toe_info.stats.tx_bytes_completed_total += tcp->tx_con->bytes_comp_cnt;
        pdev->toe_info.stats.tx_rq_bufs_completed += tcp->tx_con->buffer_completed_cnt;
        pdev->toe_info.stats.total_tx_abortion_under_flr += tcp->tx_con->abortion_under_flr;

        pdev->toe_info.stats.rx_rq_complete_calls += tcp->rx_con->rq_completion_calls;
        pdev->toe_info.stats.rx_rq_bufs_completed += tcp->rx_con->buffer_completed_cnt;
        pdev->toe_info.stats.rx_bytes_completed_total += tcp->rx_con->bytes_comp_cnt;

        pdev->toe_info.stats.rx_accepted_indications += tcp->rx_con->u.rx.gen_info.num_success_indicates;
        pdev->toe_info.stats.rx_bufs_indicated_accepted += tcp->rx_con->u.rx.gen_info.num_buffers_indicated;
        pdev->toe_info.stats.rx_bytes_indicated_accepted += tcp->rx_con->u.rx.gen_info.bytes_indicated_accepted;

        pdev->toe_info.stats.rx_rejected_indications += tcp->rx_con->u.rx.gen_info.num_failed_indicates;
        pdev->toe_info.stats.rx_bufs_indicated_rejected += tcp->rx_con->u.rx.gen_info.bufs_indicated_rejected;
        pdev->toe_info.stats.rx_bytes_indicated_rejected += tcp->rx_con->u.rx.gen_info.bytes_indicated_rejected;
        pdev->toe_info.stats.total_num_non_full_indications += tcp->rx_con->u.rx.gen_info.num_non_full_indications;

        pdev->toe_info.stats.rx_zero_byte_recv_reqs += tcp->rx_con->u.rx.rx_zero_byte_recv_reqs;
        pdev->toe_info.stats.rx_bufs_copied_grq += tcp->rx_con->u.rx.gen_info.num_buffers_copied_grq;
        pdev->toe_info.stats.rx_bufs_copied_rq += tcp->rx_con->u.rx.gen_info.num_buffers_copied_rq;
        pdev->toe_info.stats.rx_bytes_copied_in_comp += tcp->rx_con->u.rx.gen_info.bytes_copied_cnt_in_comp;
        pdev->toe_info.stats.rx_bytes_copied_in_post += tcp->rx_con->u.rx.gen_info.bytes_copied_cnt_in_post;
        pdev->toe_info.stats.rx_bytes_copied_in_process += tcp->rx_con->u.rx.gen_info.bytes_copied_cnt_in_process;
        if (pdev->toe_info.stats.max_number_of_isles_in_single_con < tcp->rx_con->u.rx.gen_info.max_number_of_isles) {
            pdev->toe_info.stats.max_number_of_isles_in_single_con = tcp->rx_con->u.rx.gen_info.max_number_of_isles;
        }
        pdev->toe_info.stats.rx_bufs_posted_total += tcp->rx_con->buffer_post_cnt;
        pdev->toe_info.stats.rx_bytes_posted_total += tcp->rx_con->bytes_post_cnt;
        pdev->toe_info.stats.rx_bufs_skipped_post += tcp->rx_con->buffer_skip_post_cnt;
        pdev->toe_info.stats.rx_bytes_skipped_post += tcp->rx_con->bytes_skip_post_cnt;

        pdev->toe_info.stats.rx_bytes_skipped_push += tcp->rx_con->bytes_push_skip_cnt;
        pdev->toe_info.stats.rx_partially_completed_buf_cnt += tcp->rx_con->partially_completed_buf_cnt;
        pdev->toe_info.stats.total_droped_empty_isles += tcp->rx_con->droped_empty_isles;
        pdev->toe_info.stats.total_droped_non_empty_isles += tcp->rx_con->droped_non_empty_isles;
        pdev->toe_info.stats.total_rx_post_blocked += tcp->rx_con->rx_post_blocked;
        pdev->toe_info.stats.total_zb_rx_post_blocked += tcp->rx_con->zb_rx_post_blocked;
        if (tcp->aux_mem_flag & TCP_CON_AUX_RT_MEM_SUCCSESS_ALLOCATION) {
            pdev->toe_info.stats.total_aux_mem_success_allocations++;
        } else if (tcp->aux_mem_flag & TCP_CON_AUX_RT_MEM_FAILED_ALLOCATION) {
            pdev->toe_info.stats.total_aux_mem_failed_allocations++;
        }
        pdev->toe_info.stats.total_rx_abortion_under_flr += tcp->rx_con->abortion_under_flr;
    }
}



/* Desciption:
 *  delete tcp state from lm _except_ from actual freeing of memory.
 *  the task of freeing of memory is done in lm_tcp_free_tcp_state()
 * Assumptions:
 *  global toe lock is taken by the caller
 */
void lm_tcp_del_tcp_state(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_del_tcp_state\n");
    DbgBreakIf(!(pdev && tcp));

    if (!lm_fl_reset_is_inprogress(pdev))
    {
        DbgBreakIf(tcp->hdr.status >= STATE_STATUS_OFFLOAD_PENDING &&
               tcp->hdr.status < STATE_STATUS_UPLOAD_DONE);
    }
    else
    {
        DbgMessage(pdev, FATAL, "###lm_tcp_del_tcp_state under FLR\n");
    }

    /* just a moment before we delete this connection, lets take it's info... */
    lm_tcp_collect_stats(pdev, tcp);

    d_list_remove_entry(
        &tcp->hdr.state_blk->tcp_list,
        &tcp->hdr.link);

    if (tcp->ulp_type == TOE_CONNECTION_TYPE)
    {
        pdev->toe_info.stats.total_upld++;
    }
    else if (tcp->ulp_type == ISCSI_CONNECTION_TYPE)
    {
        pdev->iscsi_info.run_time.stats.total_upld++;
    }

    if (!lm_fl_reset_is_inprogress(pdev) && (tcp->path != NULL)) {
        /* This is called as a result of a failured offload and not an upload...,
         * if connection is uploaded it means that path must have been taken care of
         * already. */
        DbgBreakIf((tcp->hdr.status != STATE_STATUS_INIT_OFFLOAD_ERR) &&
                   (tcp->hdr.status != STATE_STATUS_INIT) &&
                   (tcp->hdr.status != STATE_STATUS_INIT_CONTEXT));
        DbgBreakIf(tcp->path->hdr.status != STATE_STATUS_NORMAL);
        tcp->path->num_dependents--;
        tcp->path = NULL;
    }

    if (tcp->in_searcher) {
        /* remove 4tuple from searcher */
        lm_searcher_mirror_hash_remove(pdev, tcp->cid);
        tcp->in_searcher = 0;
    }

    if (tcp->cid != 0) {
        u8_t notify_fw = 0;

        /* we only notify FW if this delete is a result of upload, otherwise
         * (err_offload / error in init stage) we don't*/
        if (!lm_fl_reset_is_inprogress(pdev) && (tcp->hdr.status == STATE_STATUS_UPLOAD_DONE)) {
            notify_fw = 1;
        }
        lm_free_cid_resc(pdev, TOE_CONNECTION_TYPE, tcp->cid, notify_fw);
    }

    tcp->hdr.state_blk     = NULL;
    tcp->cid = 0;
    tcp->ctx_virt = NULL;
    tcp->ctx_phys.as_u64 = 0;
    if (tcp->aux_memory != NULL) {
        switch (tcp->type_of_aux_memory) {
        case TCP_CON_AUX_RT_MEM:
            DbgMessage(pdev, WARNl4sp,
                        "###lm_tcp_del_tcp_state: delete aux_mem (%d)\n",
                        tcp->aux_mem_size);
            tcp->type_of_aux_memory = 0;
            mm_rt_free_mem(pdev,tcp->aux_memory,tcp->aux_mem_size,LM_RESOURCE_NDIS);
            break;
        default:
            break;
        }
    }
} /* lm_tcp_del_tcp_state */

/* Desciption:
 *  delete path state from lm
 * Assumptions:
 *  global toe lock is taken by the caller
 */
void lm_tcp_del_path_state(
    struct _lm_device_t *pdev,
    lm_path_state_t *path)
{
    UNREFERENCED_PARAMETER_(pdev);

    if (path->neigh != NULL) {

        DbgBreakIf(path->neigh->hdr.status != STATE_STATUS_NORMAL);
        /* This is called as a result of a synchronous path upload */
        path->neigh->num_dependents--;
        path->neigh = NULL;
    }

    DbgBreakIf(!lm_fl_reset_is_inprogress(pdev) && (path->hdr.status != STATE_STATUS_UPLOAD_DONE));
    d_list_remove_entry(&path->hdr.state_blk->path_list, &path->hdr.link);
}

/* Desciption:
 *  delete neigh state from lm
 * Assumptions:
 *  global toe lock is taken by the caller
 */
void lm_tcp_del_neigh_state(
    struct _lm_device_t *pdev,
    lm_neigh_state_t *neigh)
{
    UNREFERENCED_PARAMETER_(pdev);

    DbgBreakIf(!lm_fl_reset_is_inprogress(pdev) && (neigh->hdr.status != STATE_STATUS_UPLOAD_DONE));
    d_list_remove_entry(&neigh->hdr.state_blk->neigh_list, &neigh->hdr.link);
}

/* Desciption:
 *  free lm tcp state resources
 * Assumptions:
 *  lm_tcp_del_tcp_state() already called  */
void lm_tcp_free_tcp_resc(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp)
{
    lm_tcp_con_t *tcp_con;
    d_list_t      released_list_of_gen_bufs;
    u8_t reset_in_progress = lm_reset_is_inprogress(pdev);
    u32_t   num_isles = 0;
    u32_t   num_bytes_in_isles = 0;
    u32_t   num_gen_bufs_in_isles = 0;

    DbgMessage(pdev, VERBOSEl4sp, "###lm_tcp_free_tcp_resc tcp=%p\n", tcp);
    DbgBreakIf(!(pdev && tcp));
    DbgBreakIf(!reset_in_progress && tcp->hdr.status >= STATE_STATUS_OFFLOAD_PENDING &&
               tcp->hdr.status < STATE_STATUS_UPLOAD_DONE);
    DbgBreakIf(tcp->cid); /* i.e lm_tcp_del_tcp_state wasn't called */

    tcp_con = tcp->rx_con;
    if (tcp_con) {
        /* need to return the generic buffers of the isle list to the pool */
        d_list_init(&released_list_of_gen_bufs, NULL, NULL, 0);
        num_isles = d_list_entry_cnt(&tcp_con->u.rx.gen_info.isles_list);
        num_bytes_in_isles = tcp_con->u.rx.gen_info.isle_nbytes;
        lm_tcp_rx_clear_isles(pdev, tcp, &released_list_of_gen_bufs);
        num_gen_bufs_in_isles = d_list_entry_cnt(&released_list_of_gen_bufs);
        if(!d_list_is_empty(&tcp_con->u.rx.gen_info.dpc_peninsula_list)) {
            if (!reset_in_progress) {
                DbgBreak();
            }
            d_list_add_tail(&released_list_of_gen_bufs,&tcp_con->u.rx.gen_info.dpc_peninsula_list);
            d_list_init(&tcp->rx_con->u.rx.gen_info.dpc_peninsula_list, NULL, NULL, 0);
        }
        if (!d_list_is_empty(&tcp_con->u.rx.gen_info.peninsula_list)) {
            d_list_add_tail(&released_list_of_gen_bufs,&tcp_con->u.rx.gen_info.peninsula_list);
            d_list_init(&tcp->rx_con->u.rx.gen_info.peninsula_list, NULL, NULL, 0);
            if (!reset_in_progress) {
                /* we can only have data in the peninsula if we didn't go via the upload flow (i.e. offload failure of some sort...)*/
                DbgBreakIf(tcp->hdr.status == STATE_STATUS_UPLOAD_DONE);
                if (tcp->hdr.status == STATE_STATUS_UPLOAD_DONE) {
                    pdev->toe_info.stats.total_bytes_lost_on_upload += tcp_con->u.rx.gen_info.peninsula_nbytes;
                }
            }
        }

        if (!d_list_is_empty(&released_list_of_gen_bufs)) {
            mm_tcp_return_list_of_gen_bufs(pdev, &released_list_of_gen_bufs, 0, NON_EXISTENT_SB_IDX);
            if (!reset_in_progress && num_isles) {
                s32_t delta = -(s32_t)num_gen_bufs_in_isles;
                MM_ACQUIRE_ISLES_CONTROL_LOCK(pdev);
                lm_tcp_update_isles_cnts(pdev, -(s32_t)num_isles, delta);
                MM_RELEASE_ISLES_CONTROL_LOCK(pdev);
            }
        }
    }

} /* lm_tcp_free_tcp_resc */

/* Desciption:
 *  update chip internal memory and hw with given offload params
 * Assumptions:
 *  - lm_tcp_init was already called
 * Returns:
 *  SUCCESS or any failure  */
lm_status_t
lm_tcp_set_ofld_params(
    lm_device_t *pdev,
    lm_state_block_t *state_blk,
    l4_ofld_params_t *params)
{
    l4_ofld_params_t *curr_params = &pdev->ofld_info.l4_params;

    UNREFERENCED_PARAMETER_(state_blk);

    DbgMessage(pdev, VERBOSE, "###lm_tcp_set_ofld_params\n");

    /* we assume all timers periods can't be 0 */
    DbgBreakIf(!(params->delayed_ack_ticks &&
                 params->nce_stale_ticks &&
                 params->push_ticks &&
                 params->sws_prevention_ticks &&
                 params->ticks_per_second));

    /* <MichalK> Here we override the ofld info. This in theory effects iscsi as well, however, since ftsk
     * does not really use timers, and passes '0' for ka / rt in delegate/cached params its ok that
     * we're overriding the parameters here. The correct solution is to maintain this per cli-idx, 
     * but that will require major changes in l4 context initialization and not worth the effort. 
     */
    *curr_params = *params;

    /* update internal memory/hw for each storm both with
     * toe/rdma/iscsi common params and with toe private params (where applicable) */

    _lm_set_ofld_params_xstorm_common(pdev, curr_params);

    _lm_set_ofld_params_tstorm_common(pdev, curr_params);

    _lm_set_ofld_params_tstorm_toe(pdev, curr_params);

    _lm_set_ofld_params_ustorm_toe(pdev, curr_params);

    _lm_set_ofld_params_xstorm_toe(pdev, curr_params);

    /* GilR 6/7/2006 - TBD - usage of params->starting_ip_id is not clear. currenlty we ignore it */

    return LM_STATUS_SUCCESS;
} /* lm_tcp_set_ofld_params */


/** Description
 *  indicates that a rst request was received. Called from several
 *  functions. Could also be called as a result of a delayed rst.
 *  Assumptions:
 */
void lm_tcp_indicate_rst_received(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp
    )
{
    lm_tcp_con_t *rx_con, *tx_con;
    u8_t ip_version;
    MM_INIT_TCP_LOCK_HANDLE();

    //DbgMessage(pdev, WARNl4rx , "##lm_tcp_indicate_rst_received cid=%d\n", tcp->cid);

    /* Update the Reset Received statistic*/
    ip_version = (tcp->path->path_const.ip_version == IP_VERSION_IPV4)? STATS_IP_4_IDX : STATS_IP_6_IDX;
    LM_COMMON_DRV_STATS_ATOMIC_INC_TOE(pdev, ipv[ip_version].in_reset);

    rx_con = tcp->rx_con;
    tx_con = tcp->tx_con;

    DbgBreakIf( ! (pdev && tcp) );
    /* The state may only be NORMAL or UPLOAD_PENDING */
    DbgBreakIf( (tcp->hdr.status != STATE_STATUS_NORMAL) &&
                (tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING) );

    /* Get the global TOE lock */
    MM_ACQUIRE_TOE_LOCK(pdev);

    /* Change the state status if needed: NORMAL->ABORTED */
    if ( tcp->hdr.status == STATE_STATUS_NORMAL ) {
        tcp->hdr.status = STATE_STATUS_ABORTED;
    }

    /* Release the global TOE lock */
    MM_RELEASE_TOE_LOCK(pdev);
/*********************** Tx **********************/
    /* Take Tx lock */
    mm_acquire_tcp_lock(pdev, tx_con);

    /* Implies POST Tx blocked */
    DbgBreakIf(tx_con->flags & TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED);
    tx_con->flags |= TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED;

    /* Abort Tx buffers */
    lm_tcp_abort_bufs(pdev, tcp, tx_con, LM_STATUS_CONNECTION_RESET);

    /* Clear delayed RST flag */
    tx_con->u.tx.flags &= ~ TCP_CON_RST_IND_NOT_SAFE;

    /* Release Tx lock */
    mm_release_tcp_lock(pdev, tx_con);
/*********************** Rx **********************/
    /* Take Rx lock */
    mm_acquire_tcp_lock(pdev, rx_con);

    /* Clear delayed FIN and RST */
    rx_con->u.rx.flags &= ~ (TCP_CON_RST_IND_PENDING | TCP_CON_FIN_IND_PENDING);

    /* Implies POST Rx blocked */
    DbgBreakIf(rx_con->flags & TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED);
    rx_con->flags |= TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED;

    /* Abort Rx buffers */
    lm_tcp_abort_bufs(pdev, tcp, rx_con, LM_STATUS_CONNECTION_RESET);

    /* Release Rx lock */
    mm_release_tcp_lock(pdev, rx_con);

    /* Indicate the Remote Abortive Disconnect to the Client */
    mm_tcp_indicate_rst_received(pdev, tcp);
}

void lm_tcp_searcher_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp
    )
{
    lm_tcp_slow_path_request_t * request = tcp->sp_request;

    DbgMessage(pdev, VERBOSEl4, "## lm_tcp_searcher_ramrod_comp\n");

    DbgBreakIf(tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING);
    DbgBreakIf(request->type != SP_REQUEST_TERMINATE_OFFLOAD);

    tcp->sp_request = NULL;
    request->type = SP_REQUEST_TERMINATE1_OFFLOAD;


    MM_ACQUIRE_TOE_LOCK(pdev);
    /* remove 4tuple from searcher */
    DbgBreakIf(!tcp->in_searcher);
    lm_searcher_mirror_hash_remove(pdev, tcp->cid);
    tcp->in_searcher = 0;
    DbgBreakIf(!(tcp->sp_flags & SP_TCP_SRC_REQ_POSTED));
    tcp->sp_flags |= SP_TCP_SRC_REQ_COMP;
    lm_tcp_post_slow_path_request(pdev, tcp, request);
    MM_RELEASE_TOE_LOCK(pdev);
}

void lm_tcp_terminate_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp)
{
    lm_tcp_slow_path_request_t * request = tcp->sp_request;
    MM_ACQUIRE_TOE_LOCK(pdev);
    tcp->sp_request = NULL;
    request->type = SP_REQUEST_QUERY;
    /* Clear the flags */
    DbgBreakIf(tcp->sp_flags & ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX ));

    DbgBreakIf(!(tcp->sp_flags & SP_TCP_TRM_REQ_POSTED));
    tcp->sp_flags |= SP_TCP_TRM_REQ_COMP;

    /* Part of the fast-terminate flow is to zeroize the timers context: turn of num of active timers  */
    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        RESET_FLAGS(((struct toe_context *)tcp->ctx_virt)->timers_context.flags, __TIMERS_BLOCK_CONTEXT_NUM_OF_ACTIVE_TIMERS);
    }

    lm_tcp_post_slow_path_request(pdev, tcp, request);

    MM_RELEASE_TOE_LOCK(pdev);
}

static void lm_tcp_rx_terminate_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp)
{
    lm_tcp_con_t * rx_con = tcp->rx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4rx, "## lm_tcp_terminate_ramrod_comp_rx\n");

    DbgBreakIf(tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING);

    mm_acquire_tcp_lock(pdev, rx_con);
    DbgBreakIf( mm_tcp_indicating_bufs(rx_con) );
    DbgBreakIf(rx_con->flags & TCP_TRM_REQ_COMPLETED);
    rx_con->flags |= TCP_TRM_REQ_COMPLETED;
    mm_release_tcp_lock(pdev, rx_con);
}

static void lm_tcp_tx_terminate_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp)
{
    lm_tcp_con_t * tx_con = tcp->tx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4tx, "## lm_tcp_terminate_ramrod_comp_tx\n");

    DbgBreakIf(tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING);

    mm_acquire_tcp_lock(pdev, tx_con);
    DbgBreakIf(tx_con->flags & TCP_TRM_REQ_COMPLETED);
    tx_con->flags |= TCP_TRM_REQ_COMPLETED;
    mm_release_tcp_lock(pdev, tx_con);

}

/** Description
 *  indicates that a fin request was received. Called from several
 *  functions. Could also be called as a result of a delayed fin
 *  Assumptions: called without any lock taken
 */
static void lm_tcp_indicate_fin_received(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp
    )
{
    lm_tcp_con_t        * rx_con;
    u8_t ip_version;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4rx , "##lm_tcp_indicate_fin_received cid=%d\n", tcp->cid);
    DbgBreakIf( ! ( pdev && tcp ) );

    ip_version = (tcp->path->path_const.ip_version == IP_VERSION_IPV4)? STATS_IP_4_IDX : STATS_IP_6_IDX;
    LM_COMMON_DRV_STATS_ATOMIC_INC_TOE(pdev, ipv[ip_version].in_fin);

    rx_con = tcp->rx_con;

    mm_acquire_tcp_lock(pdev, rx_con);

    rx_con->u.rx.flags &= ~TCP_CON_FIN_IND_PENDING;

    /* Mark the connection as POST_BLOCKED due to Remote FIN Received */
    DbgBreakIf(rx_con->flags & TCP_REMOTE_FIN_RECEIVED_ALL_RX_INDICATED);
    rx_con->flags |= TCP_REMOTE_FIN_RECEIVED_ALL_RX_INDICATED;
    /* Abort pending Rx buffers */
    lm_tcp_abort_bufs(pdev, tcp, rx_con, LM_STATUS_SUCCESS);

    mm_release_tcp_lock(pdev, rx_con);

    /* Indicate the Remote FIN up to the client */
    mm_tcp_indicate_fin_received(pdev, tcp);
}

void lm_tcp_process_retrieve_indication_cqe(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    l4_upload_reason_t    upload_reason)
{
    u32_t rx_flags = 0;
    u32_t tx_flags = 0;
    DbgMessage(pdev, INFORMl4, "###lm_tcp_process_retrieve_indication_cqe cid=%d upload_reason=%d\n", tcp->cid, upload_reason);

    /* assert that this CQE is allowed */
    /* we could receive this cqe after a RST / UPL, in which cases we will not notify about it. */
    SET_FLAGS(rx_flags, TCP_RX_COMP_BLOCKED | TCP_UPLOAD_REQUESTED);
    SET_FLAGS(tx_flags, TCP_TX_COMP_BLOCKED);

    /* we do need to notify about it even if it's after a FIN... */
    RESET_FLAGS(rx_flags, TCP_REMOTE_FIN_RECEIVED);
    RESET_FLAGS(tx_flags, TCP_FIN_REQ_COMPLETED);

    if (!GET_FLAGS(tcp->rx_con->flags, rx_flags) && !GET_FLAGS(tcp->tx_con->flags,tx_flags)) {
        SET_FLAGS(tcp->rx_con->flags, TCP_UPLOAD_REQUESTED);
        DbgMessage(pdev, INFORMl4, "###Indicating UP: cid=%d upload_reason=%d\n", tcp->cid, upload_reason);
        mm_tcp_indicate_retrieve_indication(pdev, tcp, upload_reason);
    }
}

/* Assumption: called without any lock taken */
static void lm_tcp_rx_fin_received_complete(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u8_t                  upload
    )
{
    lm_tcp_con_t * rx_con;
    u8_t indicate = 1;
    u8_t is_empty_peninsula;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4rx, "###lm_tcp_rx_fin_received_complete cid=%d\n", tcp->cid);
    DbgBreakIf( ! (pdev && tcp) );
    DbgBreakIf( tcp->hdr.status != STATE_STATUS_NORMAL && tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING);

    rx_con = tcp->rx_con;

    mm_acquire_tcp_lock(pdev, rx_con);

    /* break if we received a fin on the cqe and we still have an 'unreleased' generic buffer in our peninsula */
    DbgBreakIf( !d_list_is_empty(&tcp->rx_con->u.rx.gen_info.dpc_peninsula_list) );

    /* Mark the connection as 'COMP_BLOCKED' and 'DB BLOCKED'  */
    DbgBreakIf(rx_con->flags & TCP_REMOTE_FIN_RECEIVED);
    rx_con->flags |= TCP_REMOTE_FIN_RECEIVED;
    is_empty_peninsula = (rx_con->u.rx.gen_info.peninsula_nbytes > 0 ? 0 : 1);
    if (!is_empty_peninsula || mm_tcp_indicating_bufs(rx_con) ) {
        DbgMessage(pdev, INFORMl4, "lm_tcp_process_fin_received_cqe - postponing fin indication cid=%d\n", tcp->cid);
        rx_con->u.rx.flags |= TCP_CON_FIN_IND_PENDING;
        indicate = 0;
    }

    tcp->tcp_state_calc.fin_reception_time = mm_get_current_time(pdev);
    if (tcp->tcp_state_calc.fin_reception_time == tcp->tcp_state_calc.fin_request_time) {
        tcp->tcp_state_calc.fin_request_time -= 1;
    }

    mm_release_tcp_lock(pdev, rx_con);

    if (indicate)
    {
        lm_tcp_indicate_fin_received(pdev, tcp);
    } else if(upload && !is_empty_peninsula)
    {
        /* we did not indicate the received fin, AND we got upload request from FW, AND peninsula is not empty,
           i.e. we _may_ be waiting for RQ buffers to be posted before we indicate the fin.
           Thus, we _may_ need to request for upload:  */

        /* imitate as if FW has sent an upload request CQE: */
        lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
        pdev->toe_info.stats.total_fin_upld_requested++;
    }
}


static void lm_tcp_comp_empty_ramrod_request(
    IN struct _lm_device_t * pdev,
    IN lm_tcp_state_t      * tcp)
{
    lm_tcp_slow_path_request_t * sp_req = tcp->sp_request;

    MM_ACQUIRE_TOE_LOCK(pdev);

    DbgBreakIf(tcp->sp_flags & ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX ));
    sp_req->status = LM_STATUS_SUCCESS;
    tcp->sp_request = NULL;
    mm_tcp_comp_slow_path_request(pdev, tcp, sp_req);

    MM_RELEASE_TOE_LOCK(pdev);
}

static void lm_tcp_rx_empty_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp,
    IN    u32_t                 sp_type)
{
    u8_t indicate = 0;

    DbgBreakIf(!tcp);

    DbgMessage(pdev, INFORMl4rx | INFORMl4sp,
                "###lm_tcp_process_empty_slow_path_rcqe cid=%d, request->type=%d\n",
                tcp->cid, sp_type);

    switch (sp_type) {
    case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
    case SP_REQUEST_PENDING_TX_RST:
        break; /* relevant to scqe only */
    case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
        if ( tcp->rx_con->u.rx.flags & TCP_CON_RST_IND_PENDING ) {
            /* process it */
            MM_ACQUIRE_TOE_LOCK(pdev);

            /* Mark Rx ready for RST indication - before it was marked as 'delayed' */
            tcp->sp_flags |= REMOTE_RST_INDICATED_RX;

            if ( (tcp->sp_flags & REMOTE_RST_INDICATED_RX) && (tcp->sp_flags & REMOTE_RST_INDICATED_TX) ) {
                indicate = 1;
            }

            /* Release global TOE lock */
            MM_RELEASE_TOE_LOCK(pdev);
            if (indicate) {
                lm_tcp_indicate_rst_received(pdev, tcp);
            } /* o/w we haven't seen the TX yet... */
        }
        else if ( tcp->rx_con->u.rx.flags & TCP_CON_FIN_IND_PENDING ) {
            /* process it */
            lm_tcp_indicate_fin_received(pdev, tcp);
        }
        break;
    default:
        {
            DbgMessage(pdev, FATAL,
                    "'empty ramrod' opcode in cqe doesn't fit with sp_request->type %d\n",
                    sp_type);
            DbgBreak();
        }
    }
}

static void lm_tcp_tx_empty_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp,
    IN    u32_t                 sp_type)
{
    u8_t indicate = 0;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgBreakIf(!tcp);

    DbgMessage(pdev, INFORMl4tx | INFORMl4sp,
                "###lm_tcp_process_empty_slow_path_scqe cid=%d, request->type=%d\n",
                tcp->cid, sp_type);

    switch (sp_type) {
    case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
        /* process it */
        mm_acquire_tcp_lock(pdev, tcp->tx_con);
        lm_tcp_abort_bufs(pdev,tcp,tcp->tx_con,LM_STATUS_ABORTED);
        mm_release_tcp_lock(pdev, tcp->tx_con);
        break;
    case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
        break; /* rcqe only */
    case SP_REQUEST_PENDING_TX_RST:
        /* safe to abort buffers at this stage - we know none are pending on pbf */
        if (tcp->tx_con->u.tx.flags & TCP_CON_RST_IND_NOT_SAFE ) {
            /* process it */
            MM_ACQUIRE_TOE_LOCK(pdev);

            /* Mark Rx ready for RST indication - before it was marked as 'delayed' */
            tcp->sp_flags |= REMOTE_RST_INDICATED_TX;

            if ( (tcp->sp_flags & REMOTE_RST_INDICATED_RX) && (tcp->sp_flags & REMOTE_RST_INDICATED_TX) ) {
                indicate = 1;
            }

            mm_acquire_tcp_lock(pdev, tcp->tx_con);
            tcp->tx_con->u.tx.flags &= ~TCP_CON_RST_IND_NOT_SAFE;
            mm_release_tcp_lock(pdev, tcp->tx_con);

            /* Release global TOE lock */
            MM_RELEASE_TOE_LOCK(pdev);
            if (indicate) {
                lm_tcp_indicate_rst_received(pdev, tcp);
            } /* o/w we haven't seen the RX yet... */
        }
        break;
    default:
        {
            DbgMessage(pdev, FATAL,
                    "'empty ramrod' opcode in cqe doesn't fit with sp_request->type %d\n",
                   sp_type);
            DbgBreak();
        }
    }
}

static void lm_tcp_comp_abortive_disconnect_request(
    struct _lm_device_t        * pdev,
    lm_tcp_state_t             * tcp,
    lm_tcp_slow_path_request_t * request
    )
{
    lm_tcp_con_t *rx_con, *tx_con;
    u8_t delayed_rst = 0;
    u8_t ip_version;
    u8_t complete_sp_request = TRUE;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgBreakIf( ! (pdev && tcp && request) );

    /* Update the statistics */
    ip_version = (tcp->path->path_const.ip_version == IP_VERSION_IPV4)? STATS_IP_4_IDX : STATS_IP_6_IDX;
    LM_COMMON_DRV_STATS_ATOMIC_INC_TOE(pdev, ipv[ip_version].out_resets);

    rx_con = tcp->rx_con;
    tx_con = tcp->tx_con;

    /* Get global TOE lock */
    MM_ACQUIRE_TOE_LOCK(pdev);

    /* The state may only be NORMAL or ABORTED (due to remote RST) */
    DbgBreakIf( ( tcp->hdr.status != STATE_STATUS_NORMAL ) && ( tcp->hdr.status != STATE_STATUS_ABORTED ) );
    /* the FW will always post a RST packet no matter if
       remote RST was already received, therefore, the
       completion status of the request is always SUCCESS */
    request->status = LM_STATUS_SUCCESS;

    tcp->hdr.status = STATE_STATUS_ABORTED;

    tcp->tcp_state_calc.con_rst_flag = TRUE;

    /* Release global TOE lock */
    MM_RELEASE_TOE_LOCK(pdev);

 /***************** Tx ********************/
    /* Get Tx lock */
    mm_acquire_tcp_lock(pdev, tx_con);

    /* Clear delayed RST flag */
    tx_con->u.tx.flags &= ~ TCP_CON_RST_IND_NOT_SAFE;
    /* safe to abort buffers anyway, even if we have a non-safe tx abort, since this means that a ramrod has  been sent so queues are clear */
    lm_tcp_abort_bufs(pdev,tcp,tx_con, LM_STATUS_ABORTED);

    /* Release Tx lock */
    mm_release_tcp_lock(pdev, tx_con);

/***************** Rx ********************/
    /* Get Rx lock */
    mm_acquire_tcp_lock(pdev, rx_con);

    /* 'POST/IND BLOCKED' in the request. Even a post was in the middle it must be done by now */
    if (mm_tcp_indicating_bufs(rx_con)) {
        if (pdev->params.l4_support_pending_sp_req_complete) {
            DbgBreakIf(DBG_BREAK_ON(ABORTIVE_DISCONNECT_DURING_IND));
            complete_sp_request = FALSE;
            tcp->sp_request_pending_completion = TRUE;
            tcp->pending_abortive_disconnect++;
            mm_atomic_inc(&pdev->toe_info.stats.total_aborive_disconnect_during_completion);
            DbgMessage(pdev, INFORMl4sp, "Abortive disconnect completion during indication(%d)\n", tcp->cid);
        } else {
            DbgBreak();
        }
    }

    if ( rx_con->u.rx.flags & TCP_CON_RST_IND_PENDING ) {
        delayed_rst = 1;
    }

    /* Clear delayed RST and FIN flags */
    rx_con->u.rx.flags &= ~ (TCP_CON_RST_IND_PENDING  | TCP_CON_FIN_IND_PENDING);

    lm_tcp_abort_bufs(pdev,tcp, rx_con, LM_STATUS_ABORTED);

    /* Release Rx lock */
    mm_release_tcp_lock(pdev, rx_con);
/*****************************************/

    if ( delayed_rst ) {
        /* GilR 10/15/2006 - TBD - since anyway we complete the request
          with status SUCCESS, we do not need to indicate a remote RST
          that was delayed. therefore the following call to
          mm_tcp_indicate_rst_received is canceled */
      //mm_tcp_indicate_rst_received(pdev, tcp);
    }

    if (complete_sp_request) {
        /* Get global TOE lock */
        MM_ACQUIRE_TOE_LOCK(pdev);

        DbgBreakIf(tcp->sp_flags & ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX ));

        tcp->sp_request = NULL;

        mm_tcp_comp_slow_path_request(pdev, tcp, request);

        /* Release global TOE lock */
        MM_RELEASE_TOE_LOCK(pdev);
    }
}

static void lm_tcp_rx_rst_received_complete (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp
    )
{
    lm_tcp_con_t * rx_con;
    u8_t indicate = 0;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4rx , "###lm_tcp_process_rst_received_rcqe cid=%d\n", tcp->cid);
    DbgBreakIf( ! (pdev && tcp) );
    /* The state may only be NORMAL or UPLOAD_PENDING */
    DbgBreakIf( (tcp->hdr.status != STATE_STATUS_NORMAL) &&
                (tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING) );

    rx_con = tcp->rx_con;

    /* Get global TOE lock */
    MM_ACQUIRE_TOE_LOCK(pdev);

    /* Take the Rx lock */
    mm_acquire_tcp_lock(pdev, rx_con);

    /* break if we received a rst on the cqe and we still have an 'unreleased' generic buffer in our peninsula */
    DbgBreakIf( !d_list_is_empty(&tcp->rx_con->u.rx.gen_info.dpc_peninsula_list) );


    /* This will imply RX_COMP_LOCKED and RX_DB_BLOCKED */
    DbgBreakIf(rx_con->flags & TCP_REMOTE_RST_RECEIVED);
    rx_con->flags |= TCP_REMOTE_RST_RECEIVED;

    /* Clear pending FIN */
    rx_con->u.rx.flags &= ~ TCP_CON_FIN_IND_PENDING;

    /* Check if all received data has been completed towards the Client */
    if (rx_con->u.rx.gen_info.peninsula_nbytes || mm_tcp_indicating_bufs(rx_con) ) {
        DbgMessage(pdev, INFORMl4rx , "lm_tcp_process_rst_received_cqe - postponing rst indication cid=%d\n", tcp->cid);
        rx_con->u.rx.flags |= TCP_CON_RST_IND_PENDING;
    } else {
        /* Mark Rx ready for RST indication */
        tcp->sp_flags |= REMOTE_RST_INDICATED_RX;
    }

    /* Release the Rx lock */
    mm_release_tcp_lock(pdev, rx_con);

    if ( (tcp->sp_flags & REMOTE_RST_INDICATED_RX) && (tcp->sp_flags & REMOTE_RST_INDICATED_TX) ) {
        indicate = 1;
        tcp->tcp_state_calc.con_rst_flag = TRUE;
    }

    /* Release global TOE lock */
    MM_RELEASE_TOE_LOCK(pdev);

    /* Indicate the RST to the Client if it was the second completion */
    if ( indicate ) {
        lm_tcp_indicate_rst_received(pdev,tcp);
    }
}

static void lm_tcp_tx_rst_received_complete (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp
    )
{
    lm_tcp_con_t * tx_con;
    lm_status_t lm_status;
    u8_t indicate = 0;
    u8_t send_empty_ramrod = 0;
    u8_t upload_on_fail = 0;

    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4tx, "###lm_tcp_tx_rst_received_complete cid=%d\n", tcp->cid);
    DbgBreakIf( ! (pdev && tcp) );
    /* The state may only be NORMAL or UPLOAD_PENDING */
    DbgBreakIf( (tcp->hdr.status != STATE_STATUS_NORMAL) &&
                (tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING) );

    tx_con = tcp->tx_con;

    /* Get global TOE lock */
    MM_ACQUIRE_TOE_LOCK(pdev);

    /* Take the Tx lock */
    mm_acquire_tcp_lock(pdev, tx_con);

    /* This will imply TX_COMP_LOCKED and TX_DB_BLOCKED */
    DbgBreakIf(tx_con->flags & TCP_REMOTE_RST_RECEIVED);
    tx_con->flags |= TCP_REMOTE_RST_RECEIVED;

    /* There is a potential race between receiving a reset to aborting buffers, once reset is received from te CSTORM it doesn't mean that
     * the pbf isn't trying to transmit any other buffers, to make sure that it flushes remaining buffers we need to pass a ramrod - any ramrod,
     * if the active_tb_list is not empty, if the tx post is blocked already, it means its too late, rst / fin / trm / inv were posted, so we don't
     * abort the buffers - they will be aborted later on... to make sure buffers aren't aborted we turn on the TCP_CON_RST_IND_NOT_SAFE flag. they'll
     * be aborted in terminate later on. we won't send the indication as well, we'll send it when completing terminate / empty ramrod later on.
     */
    /* Check if all received data has been completed towards the Client + terminate ramrod has not been posted yet */
    if ( s_list_entry_cnt(&tx_con->active_tb_list) > 0 ) {
        DbgMessage(pdev, INFORMl4rx, "TX lm_tcp_process_rst_received_cqe - postponing rst indication cid=%d sending empty ramrod\n", tcp->cid);
        tx_con->u.tx.flags |= TCP_CON_RST_IND_NOT_SAFE;
        /* send the empty ramrod only if we're not blocked already.
         * TCP_TX_POST_BLOCKED includes FIN_REQ_POSTED case in which we should send the empty ramrod,
         * and REMOTE_RST_RECEIVED_ALL_RX_INDICATED, TCP_POST_BLOCKED that shouldn't be set when reaching this point,
         * so we'll check all other the relevant flags.
         * here we determine whether to send the ramrod according to the lm flags, it is possible that the ramrod will be dropped later
         * in the mm_tcp_post_empty_slow_path_request() due upload request pending in the um */
        if (!(tx_con->flags & (TCP_RST_REQ_POSTED | TCP_INV_REQ_POSTED | TCP_TRM_REQ_POSTED))) {
            send_empty_ramrod = TRUE;
        }
    } else {
        /* Mark Tx ready for RST indication */
        tcp->sp_flags |= REMOTE_RST_INDICATED_TX;
    }

    /* Release the Tx lock */
    mm_release_tcp_lock(pdev, tx_con);

    if ( (tcp->sp_flags & REMOTE_RST_INDICATED_RX) && (tcp->sp_flags & REMOTE_RST_INDICATED_TX) ) {
        indicate = 1;
        tcp->tcp_state_calc.con_rst_flag = TRUE;
    } else if ( tcp->sp_flags & REMOTE_RST_INDICATED_RX ) {
        upload_on_fail = 1; /* RX is done, the only reason that TX isn't is because it has buffers to abort, if we can't postpone tx, indicate anyway. */
        tcp->tcp_state_calc.con_rst_flag = TRUE;
    }

    /* Indicate the RST to the Client if it was the second completion */
    if ( indicate ) {
        /* Release global TOE lock */
        MM_RELEASE_TOE_LOCK(pdev);

        lm_tcp_indicate_rst_received(pdev,tcp);
    } else if (send_empty_ramrod) {
        /* Send empty ramrod, only when it is complete we can complete the reset i.e. tx reset received.
         * it is possible that the ramrod will be dropped due upload request pending in the um */
        DbgMessage(pdev, INFORMl4tx, "Sending Empty Ramrod TX\n");
        lm_status = mm_tcp_post_empty_slow_path_request(pdev, tcp, SP_REQUEST_PENDING_TX_RST);

        /* Release global TOE lock */
        MM_RELEASE_TOE_LOCK(pdev);

        if ((lm_status != LM_STATUS_PENDING) && (lm_status != LM_STATUS_UPLOAD_IN_PROGRESS)) { /* we expect the posting of an empty ramrod to be pending... */
            /* This is a bit of a problem here...we don't want to risk the pbf accessing released data, so instead
             * we risk the application turning an error, we delay the abort of buffers till the terminate stage.
             * we don't remove the RST_IND_PENDING... we'll look at that before aborting buffers... */
            if (upload_on_fail) {
                DbgMessage(pdev, WARNl4sp, "Couldn't send empty ramrod on TX when we needed\n");

                /* instead of indicating the rst, which is NOT possible at this stage, ask for connection upload */
                mm_tcp_indicate_retrieve_indication(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
                pdev->toe_info.stats.total_rst_upld_requested++;
            }
        }
    }
    else
    {
        /* Release global TOE lock */
        MM_RELEASE_TOE_LOCK(pdev);
    }
}


static void lm_tcp_rx_abortive_disconnect_ramrod_complete (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp)
{
    lm_tcp_con_t * rx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4rx, "###lm_tcp_process_abortive_disconnect_request_rcqe cid=%d\n", tcp->cid);
    DbgBreakIf( ! (pdev && tcp) );

    rx_con = tcp->rx_con;

    /* Take the Rx lock */
    mm_acquire_tcp_lock(pdev, rx_con);

    /* break if we received a rst on the cqe and we still have an 'unreleased' generic buffer in our peninsula */
    DbgBreakIf( !d_list_is_empty(&tcp->rx_con->u.rx.gen_info.peninsula_list) &&
                (((lm_tcp_gen_buf_t *)(d_list_peek_tail(&tcp->rx_con->u.rx.gen_info.peninsula_list)))->placed_bytes == 0));

    /* This implies COMP_BLOCKED */
    rx_con->flags |= TCP_RST_REQ_COMPLETED;

    /* Release the Tx lock */
    mm_release_tcp_lock(pdev, rx_con);
}

static void lm_tcp_tx_abortive_disconnect_ramrod_complete (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp)
{
    lm_tcp_con_t * tx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4tx, "###lm_tcp_tx_abortive_disconnect_request_complete cid=%d\n", tcp->cid);
    DbgBreakIf( ! (pdev && tcp) );

    tx_con = tcp->tx_con;

    /* Take the Tx lock */
    mm_acquire_tcp_lock(pdev, tx_con);

    /* This implies COMP_BLOCKED */
    tx_con->flags |= TCP_RST_REQ_COMPLETED;

    /* Release the Tx lock */
    mm_release_tcp_lock(pdev, tx_con);
}



static void lm_tcp_comp_invalidate_request(
    struct _lm_device_t        * pdev,
    lm_tcp_state_t             * tcp,
    lm_tcp_slow_path_request_t * request)
{
    DbgMessage(pdev, INFORMl4sp, "### Completing invalidate request cid=%d\n", tcp->cid);

    MM_ACQUIRE_TOE_LOCK(pdev);

    DbgBreakIf(!pdev || !tcp);
    DbgBreakIf(tcp->hdr.status != STATE_STATUS_NORMAL && tcp->hdr.status != STATE_STATUS_ABORTED);

    tcp->hdr.status = STATE_STATUS_INVALIDATED;

    tcp->sp_request = NULL;

    request->status = LM_STATUS_SUCCESS;

    DbgBreakIf(tcp->sp_flags & ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX ));

    mm_tcp_comp_slow_path_request(pdev, tcp, request);

    MM_RELEASE_TOE_LOCK(pdev);
}


static void lm_tcp_tx_invalidate_ramrod_complete (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp)
{
    lm_tcp_con_t * tx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4tx, "###lm_tcp_tx_invalidate_request_complete cid=%d\n", tcp->cid);

    DbgBreakIf( ! (pdev && tcp) );

    tx_con = tcp->tx_con;

    /* Take the Tx lock */
    mm_acquire_tcp_lock(pdev, tx_con);

    /* This implies COMP_BLOCKED */
    DbgBreakIf(tx_con->flags & TCP_INV_REQ_COMPLETED);
    tx_con->flags |= TCP_INV_REQ_COMPLETED;

    /* Release the Tx lock */
    mm_release_tcp_lock(pdev, tx_con);
}


static void lm_tcp_rx_invalidate_ramrod_complete (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp)
{
    lm_tcp_con_t * rx_con;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4rx, "###lm_tcp_process_invalidate_request_rcqe cid=%d\n", tcp->cid);
    DbgBreakIf( ! (pdev && tcp) );

    rx_con = tcp->rx_con;


    /* Take the Rx lock */
    mm_acquire_tcp_lock(pdev, rx_con);
    /* 'POST/IND BLOCKED' in the request.
       Even a post was in the middle it must be done by now
       */
    DbgBreakIf( mm_tcp_indicating_bufs(rx_con) );

    /* break if we received an invalidate on the cqe and we still have an 'unreleased' generic buffer in our peninsula */
    DbgBreakIf( !d_list_is_empty(&tcp->rx_con->u.rx.gen_info.peninsula_list) &&
                (((lm_tcp_gen_buf_t *)(d_list_peek_tail(&tcp->rx_con->u.rx.gen_info.peninsula_list)))->placed_bytes == 0));

    /* This implies COMP_BLOCKED */
    DbgBreakIf(rx_con->flags & TCP_INV_REQ_COMPLETED);
    rx_con->flags |= TCP_INV_REQ_COMPLETED;

    /* Release the Rx lock */
    mm_release_tcp_lock(pdev, rx_con);
}


static void lm_tcp_get_delegated(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp,
    IN    void                * ctx_p /* context with updated data */
    )
{
    struct xstorm_toe_tcp_ag_context_section * xag_tcp = NULL;
    struct tstorm_tcp_st_context_section     * tst_tcp = NULL;
    struct xstorm_tcp_context_section        * xst_tcp = NULL;
    struct tstorm_toe_tcp_ag_context_section * tag_tcp = NULL;

    struct ustorm_toe_st_context             * ust_toe = NULL;
    struct cstorm_toe_st_context             * cst_toe = NULL;
    struct xstorm_toe_ag_context             * xag_toe = NULL;
    struct xstorm_toe_context_section        * xst_toe = NULL;

    u32_t send_wnd;
    u8_t  sanity_check;

    ASSERT_STATIC(sizeof(struct xstorm_toe_tcp_ag_context_section) == sizeof(struct xstorm_tcp_tcp_ag_context_section));
    ASSERT_STATIC(sizeof(struct tstorm_toe_tcp_ag_context_section) == sizeof(struct tstorm_tcp_tcp_ag_context_section));

    sanity_check = FALSE;

    /* Set shortcuts... and take care of driver delegated params. */
    if (tcp->ulp_type == TOE_CONNECTION_TYPE)
    {
        xst_tcp = &((struct toe_context *)ctx_p)->xstorm_st_context.context.common.tcp;
        xag_tcp = &((struct toe_context *)ctx_p)->xstorm_ag_context.tcp;
        tst_tcp = &((struct toe_context *)ctx_p)->tstorm_st_context.context.tcp;
        tag_tcp = &((struct toe_context *)ctx_p)->tstorm_ag_context.tcp;

        xst_toe = &((struct toe_context *)ctx_p)->xstorm_st_context.context.toe;
        xag_toe = &((struct toe_context *)ctx_p)->xstorm_ag_context;
        cst_toe = &((struct toe_context *)ctx_p)->cstorm_st_context.context;
        ust_toe = &((struct toe_context *)ctx_p)->ustorm_st_context.context;

        if (S32_SUB(tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge, tcp->rx_con->db_data.rx->rcv_win_right_edge) < 0) {
            /* due to window decrease issues... */
            tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge = tcp->rx_con->db_data.rx->rcv_win_right_edge;
        }

        /* RcvWnd = WndRightEgde - RcvNext */
        /* recv_win_seq is determined by the driver, and therefore is the most up-to-date value,
        * we also have to add any pending indicated bytes to this value, and this is because we don't
        * add them immediatel, only when the buffer is returned to help limit our GRQ pool. */
        tcp->tcp_delegated.recv_win_seq = tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge +
            tcp->rx_con->u.rx.gen_info.pending_indicated_bytes;

        if (!lm_reset_is_inprogress(pdev))
        {
            sanity_check = TRUE;
        }

    }
    else if (tcp->ulp_type == ISCSI_CONNECTION_TYPE)
    {
        xst_tcp = &((struct iscsi_context *)ctx_p)->xstorm_st_context.common.tcp;
        xag_tcp = (struct xstorm_toe_tcp_ag_context_section *)&((struct iscsi_context *)ctx_p)->xstorm_ag_context.tcp;
        tst_tcp = &((struct iscsi_context *)ctx_p)->tstorm_st_context.tcp;
        tag_tcp = (struct tstorm_toe_tcp_ag_context_section *)&((struct toe_context *)ctx_p)->tstorm_ag_context.tcp;

                           /* RcvWnd    =         WndRightEgde    -         RcvNext */
        tcp->tcp_delegated.recv_win_seq = tag_tcp->wnd_right_edge - tst_tcp->rcv_nxt;
    }
    else
    {
       DbgBreakMsg("lm_tcp_get_delegated: Unsupported protocol type \n") ;
       return;
    }

    /* Sanity Checks: (block below)
     * the purpose for sanity checks below, under debug only is to find a problem in FW delegated params before
     * we send them to OS in which case it may assert later on, or worse after several offloads.
     * Perform sanity checks only if chip isn't under reset... In case of error recovery for example, these delegated
     * params may be rubbish, it's ok since in the same case we'll also send a LM_STATUS_FAILURE in the upload completion.
     */
    if (sanity_check)
    {

        /* context sanity checks */
#if !defined(_VBD_CMD_)
        /* check that DMA write towards host is done */
        DbgBreakIf(((struct toe_context *)ctx_p)->ustorm_ag_context.__state == 0);
        DbgBreakIf(((struct toe_context *)ctx_p)->tstorm_ag_context.__state == 0);
        DbgBreakIf(((struct toe_context *)ctx_p)->xstorm_ag_context.__state == 0);
        /* needs to be: t <= x <= u <= drv  */
        /* driver window right edge >= ust.prev_rcv_win_right_edge >= xag.local_adv_wnd >= tag.wnd_right_edge (cyclic)*/
// apply in w2k3
//        DbgBreakIf(S32_SUB(xag_tcp->local_adv_wnd, tag_tcp->wnd_right_edge) < 0);
//        DbgBreakIf(S32_SUB(ust_toe->prev_rcv_win_right_edge, xag_tcp->local_adv_wnd) < 0);
//        DbgBreakIf(S32_SUB(tcp->rx_con->u.rx.sws_info.drv_rcv_win_right_edge, ust_toe->prev_rcv_win_right_edge) < 0);
        /* xag.snd_nxt <= xst.snd_max */
        DbgBreakIf(S32_SUB(xag_tcp->snd_nxt, xst_tcp->snd_max) > 0);
        /* xag.snd_una <= tag.snd_una <= tag.snd_max <= xst.snd_max */
        DbgBreakIf(S32_SUB(xag_tcp->snd_una, tag_tcp->snd_una) != 0);
        DbgBreakIf(S32_SUB(tag_tcp->snd_una, tag_tcp->snd_max) > 0);
        // TBD: the assert is not valid, discuess with FW regarding a change. DbgBreakIf(S32_SUB(tag_tcp->snd_max, xst_tcp->snd_max) > 0);
        /* xag.cmp_bd_start_seq <= c.cmp_bd_start_seq <= tag.snd_una */
        DbgBreakIf(S32_SUB(xag_toe->cmp_bd_start_seq, tag_tcp->snd_una) > 0);
        /* tst.rcv_nxt >= xag.ack_to_far_end */
        DbgBreakIf(S32_SUB(tst_tcp->rcv_nxt, xag_tcp->ack_to_far_end) != 0);
        /* tst.rcv_nxt >= tst.prev_seg_seq  */
        //DbgBreakIf(S32_SUB(tst_tcp->rcv_nxt, tst_tcp->prev_seg_seq) < 0);
        /* xag.cmp_bd_cons <= cst.bd_cons <= xst.tx_bd_cons <= xst.bd_prod <= Driver bd prod (16 bit cyclic) */
        DbgBreakIf(S16_SUB(xag_toe->cmp_bd_cons, cst_toe->bd_cons) > 0);
        DbgBreakIf(S16_SUB(xst_toe->tx_bd_cons, xst_toe->bd_prod) > 0);
        DbgBreakIf(S16_SUB(xst_toe->bd_prod, tcp->tx_con->db_data.tx->bds_prod) > 0);
        DbgBreakIf(S32_SUB(tag_tcp->snd_una, xag_tcp->snd_nxt) > 0);
        /* timestamp: */
        /* tst.timestamp_exists == xst.ts_enable -- ? can't find fields in fw*/

        /* tst.timestamp_recent >= xag.ts_to_echo (cyclic) */
        DbgBreakIf(S32_SUB(tst_tcp->timestamp_recent, xag_tcp->ts_to_echo) < 0);

        /* fin: ?? can't find fields in fw */
        /* if (xst.fin_sent_flag) then bds should contain bd with fin // driver flag 'sent-fin' */
        /* if (tag.fin_sent_flag) then xst.fin_sent_flag */


        /* check that rcv nxt has the expected value compared to bytes that were completed on rx application buffers and generic buffers */
/*        rx_bytes_recv = tcp->rx_con->bytes_comp_cnt +
                        tcp->rx_con->u.rx.gen_info.bytes_indicated_accepted +
                        (tcp->sp_request->ret_data.tcp_upload_data.frag_list ? tcp->sp_request->ret_data.tcp_upload_data.frag_list->size : 0) -
                        tcp->rx_con->bytes_push_skip_cnt -
        if (tcp->rx_con->flags & TCP_REMOTE_FIN_RECEIVED)
        {
            DbgBreakIf(((u32_t)(tcp->tcp_delegated.recv_next + (u32_t)rx_bytes_recv + 1) != tst_tcp->rcv_nxt));
        } else
        {
            DbgBreakIf(((u32_t)(tcp->tcp_delegated.recv_next + (u32_t)rx_bytes_recv) != tst_tcp->rcv_nxt));
        }
*/
        /* check that cstrom rel seq is equal to tstorm snd una */
        DbgBreakIf(((struct toe_context *)ctx_p)->cstorm_ag_context.rel_seq != tag_tcp->snd_una);

        /* check that snd una has the expected value compared to bytes that were completed on tx application buffers */
        DbgBreakIf((u32_t)(tcp->tcp_delegated.send_una + (u32_t)tcp->tx_con->bytes_comp_cnt + (u32_t)tcp->tx_con->bytes_trm_aborted_cnt - (u32_t)tcp->tx_con->bytes_aborted_cnt) != tag_tcp->snd_una);
#endif

    }

    /* Set the updated delegated parameters */
    tcp->tcp_delegated.recv_next      = tst_tcp->rcv_nxt;

    tcp->tcp_delegated.send_una       = tag_tcp->snd_una;
    tcp->tcp_delegated.send_next      = xag_tcp->snd_nxt;
    tcp->tcp_delegated.send_max       = xst_tcp->snd_max;
    /* recent_seg_wnd is the value received in the last packet from the other side. This means this value is scaled,
     * therefore we need to get the absolute value by 'unscaling' it */
    tcp->tcp_delegated.send_win       = (tst_tcp->recent_seg_wnd << tcp->tcp_const.snd_seg_scale)
                                        + tcp->tcp_delegated.send_una;
    send_wnd = tst_tcp->recent_seg_wnd << tcp->tcp_const.snd_seg_scale;

    /* Does not come from chip! Driver uses what the chip returned for SndWnd,
       and takes the maximum between that, all past query results for this paramter,
       and 2 * MSS.
     */
    if ( tcp->tcp_delegated.max_send_win < tcp->tcp_delegated.send_win - tcp->tcp_delegated.send_una) {
        tcp->tcp_delegated.max_send_win = tcp->tcp_delegated.send_win - tcp->tcp_delegated.send_una;
    }

    tcp->tcp_delegated.send_wl1                   = tst_tcp->prev_seg_seq;
    tcp->tcp_delegated.send_cwin                  = tst_tcp->cwnd + tcp->tcp_delegated.send_una;
    tcp->tcp_delegated.ss_thresh                  = tst_tcp->ss_thresh;

    tcp->tcp_delegated.sm_rtt    = (tst_tcp->flags1 & TSTORM_TCP_ST_CONTEXT_SECTION_RTT_SRTT)
                                   >> TSTORM_TCP_ST_CONTEXT_SECTION_RTT_SRTT_SHIFT;
    tcp->tcp_delegated.sm_delta    = (tst_tcp->flags2 & TSTORM_TCP_ST_CONTEXT_SECTION_RTT_VARIATION)
                                     >> TSTORM_TCP_ST_CONTEXT_SECTION_RTT_VARIATION_SHIFT;
    /* convert ms to ticks. */
    //16/09/2008 NirV: Assert removed, return upon fw fix
    //DbgBreakIf(tcp->tcp_delegated.sm_rtt > (35*TIMERS_TICKS_PER_SEC));
    //DbgBreakIf(tcp->tcp_delegated.sm_delta > (35*TIMERS_TICKS_PER_SEC));

    tcp->tcp_delegated.sm_rtt =
        lm_time_resolution(pdev, tcp->tcp_delegated.sm_rtt, TIMERS_TICKS_PER_SEC, pdev->ofld_info.l4_params.ticks_per_second)*8;
    tcp->tcp_delegated.sm_delta =
        lm_time_resolution(pdev, tcp->tcp_delegated.sm_delta, TIMERS_TICKS_PER_SEC, pdev->ofld_info.l4_params.ticks_per_second)*4;

    tcp->tcp_delegated.ts_recent     = tst_tcp->timestamp_recent;
    /* convert ms to ticks. */
    tcp->tcp_delegated.ts_recent_age =
        lm_time_resolution(pdev, tst_tcp->timestamp_recent_time, TSEMI_CLK1_TICKS_PER_SEC, pdev->ofld_info.l4_params.ticks_per_second);

    tcp->tcp_delegated.tstamp   = xst_tcp->ts_time_diff;
    /* convert ms to ticks. */
    tcp->tcp_delegated.total_rt =
        lm_time_resolution(pdev, tst_tcp->retransmit_start_time, TIMERS_TICKS_PER_SEC, pdev->ofld_info.l4_params.ticks_per_second);

    tcp->tcp_delegated.dup_ack_count        = tst_tcp->dup_ack_count;
    tcp->tcp_delegated.snd_wnd_probe_count  = tst_tcp->persist_probe_count;

    if(tcp->tcp_delegated.send_una == tcp->tcp_delegated.send_max && (send_wnd > 0)) { /* KA is running (?) */
        if ( (tcp->tcp_cached.tcp_flags & TCP_FLAG_ENABLE_KEEP_ALIVE)) {

           tcp->tcp_delegated.u.keep_alive.probe_cnt     = tst_tcp->ka_probe_count;

            /* convert ms to ticks. */
            tcp->tcp_delegated.u.keep_alive.timeout_delta =
            lm_time_resolution(pdev, xag_tcp->ka_timer, TIMERS_TICKS_PER_SEC, pdev->ofld_info.l4_params.ticks_per_second);

            /* ka timeout may be negative in cases that it expired and timer was armed for other purposes. In this case - we write 0 to the
             * timeout delta - OS will treat this as if timer has just expired */
            /* bugbug, for some reason, we get a 28 bit value from FW, so a value such as 0xffffff9 is actually negative... so instead of checking (the reason is that timer's block bus width is 28 bit - ariel)
             * negative - we just check if it's larger than 0x8000000*/
            if ((tcp->tcp_delegated.u.keep_alive.timeout_delta != 0xffffffff) &&
                (tcp->tcp_delegated.u.keep_alive.timeout_delta > 0x8000000)) {
                tcp->tcp_delegated.u.keep_alive.timeout_delta = 0;
            }
        } else { //ka disabled
            tcp->tcp_delegated.u.keep_alive.probe_cnt     = 0;
            tcp->tcp_delegated.u.keep_alive.timeout_delta = 0xffffffff;
        }
    } else {
        tcp->tcp_delegated.u.retransmit.num_retx      = tst_tcp->retransmit_count;
        //TBD: Ariel, why it comes from the same place as TotalRT?
        /* TODO: we need to convert retx_ms to clock ticks in VBD instead of
         * doing this conversion in NDIS (same as Teton) */

        /* rto_timer may be negative in cases that it expired and timer was armed for other purposes. In this case - we write 0 to the
         * retx_ms - OS will treat this as if timer has just expired and immediately retransmit. */
        /* bugbug, for some reason, we get a 28 bit value from FW, so a value such as 0xffffff9 is actually negative... so instead of checking
         * negative - we just check if it's larger than 0xf000000*/
        if ((xag_tcp->rto_timer != 0xffffffff) && (xag_tcp->rto_timer > 0x8000000)) {
            tcp->tcp_delegated.u.retransmit.retx_ms = 0;
        } else {
            tcp->tcp_delegated.u.retransmit.retx_ms = xag_tcp->rto_timer;
        }
    }

    /* Calculate the TCP connection state */
    tcp->tcp_delegated.con_state = lm_tcp_calc_state(pdev, tcp,
                                                     xst_tcp->tcp_params & XSTORM_TCP_CONTEXT_SECTION_FIN_SENT_FLAG ? 1 : 0);
    pdev->toe_info.stats.con_state_on_upload[tcp->tcp_delegated.con_state]++;
}


void lm_init_sp_req_type(
    struct _lm_device_t        * pdev,
    lm_tcp_state_t             * tcp,
    lm_tcp_slow_path_request_t * lm_req,
    void                       * req_input_data)
{

    UNREFERENCED_PARAMETER_(pdev);

    switch(lm_req->type) {
    case SP_REQUEST_INITIATE_OFFLOAD:
    case SP_REQUEST_TERMINATE_OFFLOAD:
    case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
    case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
    case SP_REQUEST_PENDING_TX_RST:
    case SP_REQUEST_ABORTIVE_DISCONNECT:
    case SP_REQUEST_INVALIDATE:
        break;
    case SP_REQUEST_UPDATE_TCP:
    case SP_REQUEST_UPDATE_PATH:
    case SP_REQUEST_UPDATE_NEIGH:
    case SP_REQUEST_UPDATE_PATH_RELINK:
        lm_req->sent_data.tcp_update_data.data = req_input_data;
        break;
    case SP_REQUEST_QUERY:
        DbgBreakMsg("GilR - NOT IMPLEMENTED!\n");
        break;
    default:
        DbgBreakMsg("Illegal slow path request type!\n");
    }

    /* initialize common section of the sp request */
    lm_req->sp_req_common.req_post_func = (void *)lm_tcp_post_slow_path_request;
    lm_req->sp_req_common.req_post_ctx  = tcp;
}



static void _lm_tcp_comp_upload_tcp_request (
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp
    )
{
    lm_tcp_con_t               * rx_con    = tcp->rx_con;
    lm_tcp_con_t               * tx_con    = tcp->tx_con;
    u8_t                         has_fin   = 0;
    u8_t                         has_rst   = 0;
    lm_tcp_slow_path_request_t * sp_req    = tcp->sp_request;
    lm_path_state_t            * path      = NULL;
    lm_status_t                  lm_status = LM_STATUS_SUCCESS;
    #if 0 // TODO: add WINDOW_DEC validation check in w2k3, implement upon os type identification in the lm
    #if (DBG && !defined(_VBD_CMD_) && !defined(__USER_MODE_DEBUG))
    u32_t expect_rwin;
    #endif
    #endif
    MM_INIT_TCP_LOCK_HANDLE();

    /* status will be changed only after upload completion returns from the client */

    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        /* Abort Tx buffers and pending graceful disconnect request if any */
        mm_acquire_tcp_lock(pdev, tx_con);
        lm_tcp_abort_bufs(pdev, tcp, tx_con, (tx_con->flags & TCP_CON_RST_IND_NOT_SAFE)? LM_STATUS_CONNECTION_RESET : LM_STATUS_UPLOAD_IN_PROGRESS);

        /* Remember pending RST if any */
        has_rst |= (tx_con->u.tx.flags & TCP_CON_RST_IND_NOT_SAFE) ? 1 : 0;

        /* Clear pending RST */
        tx_con->u.tx.flags &= ~(TCP_CON_RST_IND_NOT_SAFE);

        mm_release_tcp_lock(pdev, tx_con);

        /* Rx abortive part... */
        mm_acquire_tcp_lock(pdev, rx_con);
        /* Abort pending buffers */
        lm_tcp_abort_bufs(pdev, tcp, rx_con, LM_STATUS_UPLOAD_IN_PROGRESS);

        /* Remember pending FIN if any */
        has_fin = rx_con->u.rx.flags & TCP_CON_FIN_IND_PENDING ? 1 : 0;

        /* Remember pending RST if any */
        has_rst |= (rx_con->u.rx.flags & TCP_CON_RST_IND_PENDING) ? 1 : 0;

        /* Clear pending FIN and RST */
        rx_con->u.rx.flags &= ~(TCP_CON_FIN_IND_PENDING | TCP_CON_RST_IND_PENDING);

        /* Get generic data that hasn't been indicated so far */
        lm_status = lm_tcp_rx_get_buffered_data_from_terminate(pdev, tcp,
                                     &(tcp->sp_request->ret_data.tcp_upload_data.frag_list),
                                     &(tcp->sp_request->ret_data.tcp_upload_data.ret_buf_ctx)
                                     );
        mm_release_tcp_lock(pdev, rx_con);

        /* check if we have a delayed fin */
        /* assumption: if we have a delayed-fin, it means we have buffered data*/
        /* OS can't handle fin indiaction followed by buffered data */
        /* DbgBreakIf(has_fin && !sp_req->ret_data.tcp_upload_data.frag_list); */
        /* DbgBreakIf(has_rst && !sp_req->ret_data.tcp_upload_data.frag_list); */

        /* check if we have a delayed rst (rst is sp so no locks) */
        if ( has_rst ) {
            mm_tcp_indicate_rst_received(pdev, tcp);
        }
    }

    /* Indication part */
    MM_ACQUIRE_TOE_LOCK(pdev);

    DbgBreakIf(!(tcp->sp_flags & SP_TCP_QRY_REQ_POSTED));
    tcp->sp_flags |= SP_TCP_QRY_REQ_COMP;

    /* Update delegated parameters */
    lm_tcp_get_delegated(pdev, tcp, &tcp->sp_req_data.virt_addr->toe_ctx);

    tcp->sp_request = NULL;
    sp_req->status = lm_status;

    /* Indicate SP request completion up to the client */
    /* Set the request type to TERMINATE_OFFLOAD as it was set by UM during the post */
    sp_req->type = SP_REQUEST_TERMINATE_OFFLOAD;

    DbgBreakIf(tcp->path->num_dependents == 0);
    tcp->path->num_dependents--;

    // update stats counters if TOE
    if (TOE_CONNECTION_TYPE == tcp->ulp_type )
    {
        if( IP_VERSION_IPV4 == tcp->path->path_const.ip_version )
        {
            --pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[STATS_IP_4_IDX].currently_established;
        }
        else if( IP_VERSION_IPV6 == tcp->path->path_const.ip_version )
        {
            --pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[STATS_IP_6_IDX].currently_established;
        }
    }

    if (tcp->path->hdr.status == STATE_STATUS_UPLOAD_PENDING &&
        tcp->path->num_dependents == 0) {
        /* last pendind-upload-path dependent... */
        path = tcp->path;
    }
    tcp->path = NULL;

    #if 0 // TODO: add WINDOW_DEC validation check in w2k3, implement upon os type identification in the lm
    if (tcp->ulp_type == TOE_CONNECTION_TYPE) {
        #if (DBG && !defined(_VBD_CMD_) && !defined(__USER_MODE_DEBUG))
        expect_rwin = (u32_t) S32_SUB(
            tcp->tcp_delegated.recv_win_seq,
            tcp->tcp_delegated.recv_next);
        /* These asserts are not valid for WSD connections. */
        if(sp_req->ret_data.tcp_upload_data.frag_list)
        {
            expect_rwin += (u32_t)sp_req->ret_data.tcp_upload_data.frag_list->size;
        }

        /* If we received a fin / rst we may be down by one on the initial_rcv_wnd... */
        if((tcp->rx_con->flags & TCP_REMOTE_FIN_RECEIVED) ||
           (tcp->rx_con->flags & TCP_REMOTE_RST_RECEIVED))
        {
            DbgBreakIf(
                (expect_rwin != tcp->tcp_cached.initial_rcv_wnd) &&
                (expect_rwin != tcp->tcp_cached.initial_rcv_wnd - 1));
        }
        else
        {
            DbgBreakIf(expect_rwin != tcp->tcp_cached.initial_rcv_wnd);
        }
        #endif
    }
    #endif

    mm_tcp_comp_slow_path_request(pdev, tcp, sp_req);

    if (path) {
        DbgMessage(pdev, INFORMl4sp, "_lm_tcp_comp_upload_request: last tcp dependent of pending path %p\n", path);
        _lm_tcp_comp_upload_path_request(pdev, path);
    }

    MM_RELEASE_TOE_LOCK(pdev);


}

lm_tcp_state_t * lm_tcp_get_next_path_dependent(
    struct _lm_device_t *pdev,
    void   *path_state,
    lm_tcp_state_t * tcp_state)
{
    if (tcp_state == NULL) {
        tcp_state = (lm_tcp_state_t *) d_list_peek_head(&pdev->toe_info.state_blk.tcp_list);
    } else {
        tcp_state = (lm_tcp_state_t *) d_list_next_entry(&tcp_state->hdr.link);
    }

    while(tcp_state)  {
        /* Update the tcp state only if it is a dependent and is not being offloaded,
         * invalidated, or uploaded. */
        if (tcp_state->path == (lm_path_state_t*)path_state) {
            return tcp_state;
        }
        tcp_state = (lm_tcp_state_t *) d_list_next_entry(&tcp_state->hdr.link);
    }
    return NULL;

}


lm_tcp_state_t * lm_tcp_get_next_neigh_dependent(
    struct _lm_device_t *pdev,
    void * neigh_state,
    lm_tcp_state_t * tcp_state)
{
    if (tcp_state == NULL) {
        tcp_state = (lm_tcp_state_t *) d_list_peek_head(&pdev->toe_info.state_blk.tcp_list);
    } else {
        tcp_state = (lm_tcp_state_t *) d_list_next_entry(&tcp_state->hdr.link);
    }

    while(tcp_state)  {
        /* Update the tcp state only if it is a dependent and is not being offloaded,
         * invalidated, or uploaded. */
        if (tcp_state->path && (tcp_state->path->neigh == (lm_neigh_state_t*)neigh_state)) {
            return tcp_state;
        }
        tcp_state = (lm_tcp_state_t *) d_list_next_entry(&tcp_state->hdr.link);
    }
    return NULL;
}


void lm_tcp_update_ramrod_complete(lm_device_t * pdev, lm_tcp_state_t * tcp)
{
    lm_tcp_slow_path_request_t  *sp_req;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, INFORMl4sp, "###lm_tcp_update_ramrod_complete cid=%d \n", tcp->cid);

    MM_ACQUIRE_TOE_LOCK(pdev);

    /* assert state status is NORMAL */
    DbgBreakIf( (tcp->hdr.status != STATE_STATUS_NORMAL) &&
                (tcp->hdr.status != STATE_STATUS_ABORTED));
    DbgBreakIf(tcp->sp_request == NULL);
    DbgBreakIf((tcp->sp_request->type != SP_REQUEST_UPDATE_NEIGH) &&
               (tcp->sp_request->type != SP_REQUEST_UPDATE_PATH) &&
               (tcp->sp_request->type != SP_REQUEST_UPDATE_TCP) &&
               (tcp->sp_request->type != SP_REQUEST_UPDATE_PATH_RELINK));

    sp_req = tcp->sp_request;
    DbgBreakIf(tcp->sp_flags & ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX ));
    sp_req->status = LM_STATUS_SUCCESS;
    tcp->sp_request = NULL;

    /* Take the Rx lock */
    mm_acquire_tcp_lock(pdev, tcp->rx_con);
    if ((sp_req->type == SP_REQUEST_UPDATE_TCP) && (GET_FLAGS(tcp->rx_con->db_data.rx->flags, TOE_RX_DB_DATA_IGNORE_WND_UPDATES)))
    {
        lm_tcp_rx_post_sws(pdev, tcp, tcp->rx_con, tcp->rx_con->dpc_info.dpc_fw_wnd_after_dec, TCP_RX_POST_SWS_SET);
    }
    /* Release the Rx lock */
    mm_release_tcp_lock(pdev, tcp->rx_con);

    mm_tcp_comp_slow_path_request(pdev, tcp, sp_req);

    MM_RELEASE_TOE_LOCK(pdev);
}


void lm_tcp_query_ramrod_complete(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp
    )
{
    DbgMessage(pdev, VERBOSEl4, "## lm_tcp_query_ramrod_comp\n");
    DbgBreakIf(! tcp->sp_request );
    DbgBreakIf(tcp->sp_request->type != SP_REQUEST_QUERY);

    if (tcp->hdr.status == STATE_STATUS_UPLOAD_PENDING) {
        _lm_tcp_comp_upload_tcp_request(pdev, tcp);
    } else {
        DbgBreakMsg("Vladz: Not implemented yet!\n");
    }
}

/* TOE lock should be taken by hte caller */
void lm_tcp_internal_query(
    IN    struct _lm_device_t * pdev)
{
    lm_tcp_state_t *tcp_state;
    u32_t status_arr[STATE_STATUS_ERR+1] = {0};
    u32_t status, num_tcps, i;

    DbgMessage(pdev, FATAL, "## lm_tcp_debug_query START version %d.%d.%d\n",
                LM_DRIVER_MAJOR_VER, LM_DRIVER_MINOR_VER, LM_DRIVER_FIX_NUM);

    num_tcps = d_list_entry_cnt(&pdev->toe_info.state_blk.tcp_list);
    tcp_state = (lm_tcp_state_t *)d_list_peek_head(&pdev->toe_info.state_blk.tcp_list);
    i = 0;
    while (tcp_state) {
        status = tcp_state->hdr.status;
        status_arr[status]++;

        /* check state's status */
        if(status != STATE_STATUS_NORMAL) {
            DbgMessage(pdev, FATAL, "# tcp ptr 0x%p (cid %d), has status=%d (!= normal)\n",
                        tcp_state, tcp_state->cid, status);
        }

        /* verify the is no pending slow path request */
        if(tcp_state->sp_request) {
            DbgMessage(pdev, FATAL, "# tcp ptr 0x%p (cid %d), has slow path request of type %d, not completed by FW (sp comp flags=0x%x\n",
                        tcp_state, tcp_state->cid, tcp_state->sp_request->type, tcp_state->sp_flags);
        }

        /* verify the is no bytes pending completion */
        if(tcp_state->tx_con->bytes_post_cnt != tcp_state->tx_con->bytes_comp_cnt) {
            DbgMessage(pdev, FATAL, "# tcp ptr 0x%p (cid %d), has TX pending bytes (%d). (con->flags=0x%x)\n",
                        tcp_state, tcp_state->cid,
                        S64_SUB(tcp_state->tx_con->bytes_post_cnt, tcp_state->tx_con->bytes_comp_cnt),
                        tcp_state->tx_con->flags);
        }
        if(tcp_state->rx_con->bytes_post_cnt != tcp_state->rx_con->bytes_comp_cnt) {
            DbgMessage(pdev, FATAL, "# tcp ptr 0x%p (cid %d), has RX pending bytes (%d). (con->flags=0x%x)\n",
                        tcp_state, tcp_state->cid,
                        S64_SUB(tcp_state->rx_con->bytes_post_cnt, tcp_state->rx_con->bytes_comp_cnt),
                        tcp_state->rx_con->flags);
        }

        tcp_state = (lm_tcp_state_t *)d_list_next_entry((d_list_entry_t*)tcp_state);
    }

    /* print statistics */
    DbgMessage(pdev, FATAL, "# num offloaded connections=%d\n", num_tcps);
    for (i = 0; i < STATE_STATUS_ERR+1; i++) {
        if (status_arr[i]) {
            DbgMessage(pdev, FATAL, "#    num connections in status %d=%d\n", i, status_arr[i]);
        }
    }

    DbgMessage(pdev, FATAL, "## lm_tcp_debug_query END\n");
}


void lm_tcp_upld_close_received_complete(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    l4_upload_reason_t    upload_reason)
{
    DbgMessage(pdev, INFORMl4sp , "###lm_tcp_drv_upl_received_complete cid=%d \n", tcp->cid);

    MM_ACQUIRE_TOE_LOCK(pdev);

    tcp->tcp_state_calc.con_upld_close_flag = TRUE;

    MM_RELEASE_TOE_LOCK(pdev);

    lm_tcp_process_retrieve_indication_cqe(pdev, tcp, upload_reason);
    pdev->toe_info.stats.total_close_upld_requested++;
}


/** Description
 *   completes the slow-path part of a connection
 */
void lm_tcp_tx_complete_tcp_sp(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp,
    IN    lm_tcp_con_t        * con)
{
    u8_t complete_ramrod;
    u32_t sp_type,sp_flags,flags,snapshot_flags;
    lm_tcp_slow_path_request_t * request = NULL;

    snapshot_flags = con->dpc_info.snapshot_flags;
    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_RESET_RECV) {
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_RESET_RECV;
        lm_tcp_tx_rst_received_complete(pdev, con->tcp_state);
    }
    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_RAMROD_CMP) {
        /* clean the dpc_info: we're done with it */
        con->dpc_info.snapshot_flags = 0;

        /* all ramrod on SCQ also complete on RCQ*/
        complete_ramrod = FALSE;
        /* Get global TOE lock */
        MM_ACQUIRE_TOE_LOCK(pdev);

        /* save the type under the lock because the next ramrod will change this type ???*/
        sp_type = tcp->sp_request->type;
        MM_RELEASE_TOE_LOCK(pdev);

        switch(sp_type) {
        case SP_REQUEST_ABORTIVE_DISCONNECT:
            lm_tcp_tx_abortive_disconnect_ramrod_complete(pdev, tcp);
            break;
        case SP_REQUEST_INVALIDATE:
            lm_tcp_tx_invalidate_ramrod_complete(pdev, tcp);
            break;
        case SP_REQUEST_TERMINATE1_OFFLOAD:
            lm_tcp_tx_terminate_ramrod_complete(pdev, tcp);
            break;
        case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
        case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
        case SP_REQUEST_PENDING_TX_RST:
            lm_tcp_tx_empty_ramrod_complete(pdev, tcp, sp_type);
            break;
        default:
            DbgMessage(pdev, FATAL, "unexpected sp completion type=%d\n", tcp->sp_request->type);
            DbgBreak();
        }
        /* Get global TOE lock */
        MM_ACQUIRE_TOE_LOCK(pdev);

        /* save the type under the lock because the next ramrod will change this type */
        DbgBreakIf(sp_type != tcp->sp_request->type);

        tcp->sp_flags |= SP_REQUEST_COMPLETED_TX;

        /* If it's a second comletion, post the query ramrod */
        if ( tcp->sp_flags & SP_REQUEST_COMPLETED_RX ) {
            complete_ramrod = TRUE;
            tcp->sp_flags &= ~ ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX );
        }
        sp_flags = tcp->sp_flags;
        flags = tcp->tx_con->flags;
        MM_RELEASE_TOE_LOCK(pdev);
        if (complete_ramrod) {
            request = tcp->sp_request;
            DbgBreakIf(request == NULL);
            switch(sp_type) {
            case SP_REQUEST_ABORTIVE_DISCONNECT:
                DbgBreakIf(request->type != SP_REQUEST_ABORTIVE_DISCONNECT);
                lm_tcp_comp_abortive_disconnect_request(pdev, tcp, request);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_RESET_SEND, tcp->ulp_type, tcp->cid);
            break;
            case SP_REQUEST_INVALIDATE:
                DbgBreakIf(request->type != SP_REQUEST_INVALIDATE);
                lm_tcp_comp_invalidate_request(pdev, tcp, request);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_INVALIDATE, tcp->ulp_type, tcp->cid);
            break;
            case SP_REQUEST_TERMINATE1_OFFLOAD:
                DbgBreakIf(request->type != SP_REQUEST_TERMINATE1_OFFLOAD);
                lm_tcp_terminate_ramrod_complete(pdev, tcp);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_TERMINATE, tcp->ulp_type, tcp->cid);
            break;
            case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
            case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
            case SP_REQUEST_PENDING_TX_RST:
                lm_tcp_comp_empty_ramrod_request(pdev, tcp);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_EMPTY_RAMROD, tcp->ulp_type, tcp->cid);
            break;
            default:
                DbgMessage(pdev, FATAL, "unexpected sp completion type=%d\n", tcp->sp_request->type);
                DbgBreak();
            }
        }
    }
}

/** Description
 *   completes the slow-path part of a connection
 *   completes ramrods if ramrod is completed.
 *   function logic: every stage 'turns' of it's flag, if at the end of the check the flags is zero
 *   it means there is nothing left to do and we can return. Usually, we will rarely have a case of more
 *   than one/two flags on, therefore it seems useless to check all the cases (too many if/jumps)
 */
void lm_tcp_rx_complete_tcp_sp(
    IN    struct _lm_device_t * pdev,
    IN    lm_tcp_state_t      * tcp,
    IN    lm_tcp_con_t        * con
    )
{
    u8_t complete_ramrod;
    u32_t sp_type,sp_flags,flags,snapshot_flags;
    lm_tcp_slow_path_request_t * request = NULL;
    u32_t cid;
    u8_t  ulp_type;

    /* handle fin recv */
    snapshot_flags = con->dpc_info.snapshot_flags;
    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_FIN_RECV) {
        lm_tcp_rx_fin_received_complete(pdev, tcp, 0);
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_FIN_RECV;
    }
    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_FIN_RECV_UPL) {
        lm_tcp_rx_fin_received_complete(pdev, tcp, 1);
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_FIN_RECV_UPL;
    }

    DbgMessage(pdev, INFORMl4rx, "lm_tcp_rx_complete_tcp_sp tcp=%p cid=%d \n", tcp, tcp->cid);
    /* reset recv needs to be checked first */
    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_RESET_RECV) {
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_RESET_RECV;
        lm_tcp_rx_rst_received_complete(pdev, tcp);
    }

    /* check if we have some sort of retrieve indication. we sort of check twice */
    /* Rx completions (from ustorm) will not arrive after the following indications,
     * therefore, we can assume, they were received before
     * can't assume the same for ramrods */
    if (con->dpc_info.snapshot_flags & (LM_TCP_DPC_URG | LM_TCP_DPC_RT_TO | LM_TCP_DPC_KA_TO | LM_TCP_DPC_DBT_RE | LM_TCP_DPC_OPT_ERR | LM_TCP_DPC_UPLD_CLOSE)) {
        con->dpc_info.snapshot_flags &= ~(LM_TCP_DPC_TOO_BIG_ISLE | LM_TCP_DPC_TOO_MANY_ISLES);
        if (con->dpc_info.snapshot_flags & LM_TCP_DPC_URG) {
            con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_URG;
            lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_URG);
        }

        if (con->dpc_info.snapshot_flags & LM_TCP_DPC_RT_TO) {
            con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_RT_TO;
            lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_RETRANSMIT_TIMEOUT);
        }

        if (con->dpc_info.snapshot_flags & LM_TCP_DPC_KA_TO) {
            con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_KA_TO;
            lm_tcp_upld_close_received_complete(pdev, tcp, L4_UPLOAD_REASON_KEEP_ALIVE_TIMEOUT);
        }

        if (con->dpc_info.snapshot_flags & LM_TCP_DPC_DBT_RE) {
            con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_DBT_RE;
            lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
            pdev->toe_info.stats.total_dbt_upld_requested++;
        }

        if (con->dpc_info.snapshot_flags & LM_TCP_DPC_OPT_ERR) {
            con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_OPT_ERR;
            lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
            pdev->toe_info.stats.total_opt_upld_requested++;
        }

        if (con->dpc_info.snapshot_flags & LM_TCP_DPC_UPLD_CLOSE) {
            con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_UPLD_CLOSE;
            lm_tcp_upld_close_received_complete(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
        }
    } else if (con->dpc_info.snapshot_flags & LM_TCP_DPC_TOO_BIG_ISLE) {
        con->dpc_info.snapshot_flags &= ~(LM_TCP_DPC_TOO_BIG_ISLE | LM_TCP_DPC_TOO_MANY_ISLES);
        lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
        pdev->toe_info.stats.total_big_isle_upld_requesed++;
    } else if (con->dpc_info.snapshot_flags & LM_TCP_DPC_TOO_MANY_ISLES) {
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_TOO_MANY_ISLES;
        lm_tcp_process_retrieve_indication_cqe(pdev, tcp, L4_UPLOAD_REASON_UPLOAD_REQUESTED);
        pdev->toe_info.stats.total_many_isles_upld_requesed++;
    }


    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_RAMROD_CMP) {
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_RAMROD_CMP;
        DbgBreakIf(con->dpc_info.snapshot_flags != 0);
        /* Keep these before completing as the completion calls themselves can cause tcp state to be
         * deleted... */
        cid = tcp->cid;
        ulp_type = tcp->ulp_type;
        switch (tcp->sp_request->type) {
            case SP_REQUEST_UPDATE_NEIGH:
            case SP_REQUEST_UPDATE_PATH:
            case SP_REQUEST_UPDATE_TCP:
            case SP_REQUEST_UPDATE_PATH_RELINK:
                lm_tcp_update_ramrod_complete(pdev, tcp);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_UPDATE, ulp_type, cid);
                return;
            case SP_REQUEST_QUERY:
                lm_tcp_query_ramrod_complete(pdev, tcp); /*  this may delete tcp !! */
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_QUERY, ulp_type, cid);
                return;
            case SP_REQUEST_TERMINATE_OFFLOAD:
                lm_tcp_searcher_ramrod_complete(pdev, tcp);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_SEARCHER_DELETE, ulp_type, cid);
                return;
            case SP_REQUEST_INITIATE_OFFLOAD:
                /* Completion of initiate offload request can reach this point only if there was a license error, */
                /* otherwise its being completed earlier during 'process' stage                                   */
                lm_tcp_comp_initiate_offload_request(pdev, tcp, TOE_INITIATE_OFFLOAD_RAMROD_DATA_LICENSE_FAILURE);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_INITIATE_OFFLOAD, tcp->ulp_type, cid);
                return;
        }

        /* The rest of the ramrods on RCQ also complete on SCQ */
        complete_ramrod = FALSE;
        MM_ACQUIRE_TOE_LOCK(pdev);

        /* save the type under the lock because the next ramrod will change this type ????*/
        sp_type = tcp->sp_request->type;
        MM_RELEASE_TOE_LOCK(pdev);

        switch(sp_type) {
        case SP_REQUEST_ABORTIVE_DISCONNECT:
            lm_tcp_rx_abortive_disconnect_ramrod_complete(pdev, tcp);
            break;
        case SP_REQUEST_INVALIDATE:
            lm_tcp_rx_invalidate_ramrod_complete(pdev, tcp);
            break;
        case SP_REQUEST_TERMINATE1_OFFLOAD:
            lm_tcp_rx_terminate_ramrod_complete(pdev, tcp);
            break;
        case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
        case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
        case SP_REQUEST_PENDING_TX_RST:
            lm_tcp_rx_empty_ramrod_complete(pdev,tcp, sp_type);
            break;
        default:
            DbgMessage(pdev, FATAL, "unexpected sp completion type=%d\n", tcp->sp_request->type);
            DbgBreak();
        }
        /* Get global TOE lock */
        MM_ACQUIRE_TOE_LOCK(pdev);

        DbgBreakIf(sp_type != tcp->sp_request->type);

        tcp->sp_flags |= SP_REQUEST_COMPLETED_RX;

        /* If it's a second comletion, post the query ramrod */
        if ( tcp->sp_flags & SP_REQUEST_COMPLETED_TX ) {
            complete_ramrod = TRUE;
            tcp->sp_flags &= ~ ( SP_REQUEST_COMPLETED_TX | SP_REQUEST_COMPLETED_RX );
        }
        sp_flags = tcp->sp_flags;
        flags = tcp->rx_con->flags;
        MM_RELEASE_TOE_LOCK(pdev);
        if (complete_ramrod) {
            request = tcp->sp_request;
            DbgBreakIf(request == NULL);
            switch(sp_type) {
            case SP_REQUEST_ABORTIVE_DISCONNECT:
                DbgBreakIf(request->type != SP_REQUEST_ABORTIVE_DISCONNECT);
                lm_tcp_comp_abortive_disconnect_request(pdev, tcp, request);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_RESET_SEND, tcp->ulp_type, tcp->cid);
                break;
            case SP_REQUEST_INVALIDATE:
                DbgBreakIf(request->type != SP_REQUEST_INVALIDATE);
                lm_tcp_comp_invalidate_request(pdev, tcp, request);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_INVALIDATE, tcp->ulp_type, tcp->cid);
                break;
            case SP_REQUEST_TERMINATE1_OFFLOAD:
                DbgBreakIf(request->type != SP_REQUEST_TERMINATE1_OFFLOAD);
                lm_tcp_terminate_ramrod_complete(pdev, tcp);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_TERMINATE, tcp->ulp_type, tcp->cid);
                break;
            case SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT:
            case SP_REQUEST_PENDING_REMOTE_DISCONNECT:
            case SP_REQUEST_PENDING_TX_RST:
                lm_tcp_comp_empty_ramrod_request(pdev, tcp);
                lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_EMPTY_RAMROD, tcp->ulp_type, tcp->cid);
                break;
            default:
                DbgMessage(pdev, FATAL, "unexpected sp completion type=%d\n", tcp->sp_request->type);
                DbgBreak();
            }
        }
    }
}

#define MSL        4  /* 4 seconds */

l4_tcp_con_state_t lm_tcp_calc_state (
    lm_device_t    * pdev,
    lm_tcp_state_t * tcp,
    u8_t             fin_was_sent
    )
{
    enum {
        NO_CLOSE = 0,
        ACTIVE_CLOSE,
        PASSIVE_CLOSE,
        PASSIVE_BY_ACTIVE_CLOSE
    } closing_type;

    u32_t snd_max = tcp->tcp_delegated.send_max;
    u32_t snd_una = tcp->tcp_delegated.send_una;
    u8_t  con_rst = tcp->tcp_state_calc.con_rst_flag;
    u8_t  con_upld_close = tcp->tcp_state_calc.con_upld_close_flag;
    u64_t fin_completed_time = tcp->tcp_state_calc.fin_completed_time;
    u64_t fin_reception_time = tcp->tcp_state_calc.fin_reception_time;
    u64_t fin_request_time = tcp->tcp_state_calc.fin_request_time;
    u64_t time_wait_state_entering_time = fin_completed_time > fin_reception_time ?
                                      fin_completed_time : fin_reception_time;
    l4_tcp_con_state_t tcp_state;

    /* Set closing type */
    closing_type = NO_CLOSE;
    if ( fin_reception_time == 0 ) {
        if ( fin_request_time > 0 ) {
            closing_type = ACTIVE_CLOSE;
        }
    } else if ( ( fin_reception_time < fin_request_time ) || (fin_request_time == 0) ) {
        closing_type = PASSIVE_CLOSE;
    } else if ( ( fin_reception_time >= fin_request_time ) && (fin_request_time > 0) ){
        closing_type = PASSIVE_BY_ACTIVE_CLOSE;
    }

    if ((con_rst) || (con_upld_close)) {
        tcp_state = L4_TCP_CON_STATE_CLOSED;
    } else if ( closing_type == NO_CLOSE ) {
        tcp_state = L4_TCP_CON_STATE_ESTABLISHED;
    } else if ( ( closing_type == ACTIVE_CLOSE ) && fin_was_sent ) {
        if  ( snd_una == snd_max ){
            tcp_state = L4_TCP_CON_STATE_FIN_WAIT2;
        } else {
            tcp_state = L4_TCP_CON_STATE_FIN_WAIT1;
        }
    } else if ( ( closing_type == PASSIVE_BY_ACTIVE_CLOSE ) && (! fin_was_sent ) ) {
        tcp_state = L4_TCP_CON_STATE_CLOSE_WAIT;
    } else if (closing_type == PASSIVE_BY_ACTIVE_CLOSE ) {
        if (snd_una == snd_max) {
            if ( mm_get_current_time(pdev) - time_wait_state_entering_time > 2*pdev->ofld_info.l4_params.ticks_per_second *MSL ) {
                tcp_state = L4_TCP_CON_STATE_CLOSED;
            } else  {
                tcp_state = L4_TCP_CON_STATE_TIME_WAIT;
            }
        } else {
            tcp_state = L4_TCP_CON_STATE_CLOSING;
        }
    } else if (closing_type == PASSIVE_CLOSE ) {
            if ( ! fin_was_sent ) {
                tcp_state = L4_TCP_CON_STATE_CLOSE_WAIT;
            } else if ( snd_una == snd_max ) {
                tcp_state = L4_TCP_CON_STATE_CLOSED;
            } else {
                tcp_state = L4_TCP_CON_STATE_LAST_ACK;
            }
    } else {
        tcp_state = L4_TCP_CON_STATE_ESTABLISHED;
    }

    return tcp_state;
}

void lm_tcp_clear_grqs(lm_device_t * pdev)
{
    lm_tcp_grq_t     * grq;
//    lm_tcp_gen_buf_t * gen_buf;
    u8_t              idx;

    DbgBreakIf(!(pdev->params.ofld_cap & LM_OFFLOAD_CHIMNEY));

    /* shutdown bug - BSOD only if shutdown is not in progress */
    if (!lm_reset_is_inprogress(pdev)){
        DbgBreakIf(!d_list_is_empty(&pdev->toe_info.state_blk.tcp_list));
        DbgBreakIf(!d_list_is_empty(&pdev->toe_info.state_blk.path_list));
        DbgBreakIf(!d_list_is_empty(&pdev->toe_info.state_blk.neigh_list));
    }

    /* we need to go over all the buffers in the GRQs and return them to the pool. We also need
     * to clear the consumer- of the grq in the FWto make sure this grq isn't treated in the xon test. */
    /* This function is called after all work - items have finished, and the driver
     * state is no longer running, therefore there is no risk at accessing the grqs without
     * a lock */

    if (IS_PFDEV(pdev)) {
        DbgBreakIf(USTORM_TOE_GRQ_CONS_PTR_LO_SIZE != 4);
        DbgBreakIf(USTORM_TOE_GRQ_CONS_PTR_HI_SIZE != 4);
    }

    LM_TOE_FOREACH_RSS_IDX(pdev, idx)
    {
        grq = &pdev->toe_info.grqs[idx];
        MM_ACQUIRE_TOE_GRQ_LOCK(pdev, idx);
        grq->grq_compensate_on_alloc = FALSE;
        MM_RELEASE_TOE_GRQ_LOCK(pdev, idx);
    }

    LM_TOE_FOREACH_RSS_IDX(pdev, idx)
    {
        if (IS_PFDEV(pdev)) {
           /* nullify consumer pointer of all inactive GRQs (required by FW) (will override with active ones)  */
            LM_INTMEM_WRITE32(pdev, USTORM_TOE_GRQ_CONS_PTR_LO_OFFSET(LM_TOE_FW_RSS_ID(pdev,idx), PORT_ID(pdev)), 0, BAR_USTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev, USTORM_TOE_GRQ_CONS_PTR_HI_OFFSET(LM_TOE_FW_RSS_ID(pdev,idx), PORT_ID(pdev)), 0, BAR_USTRORM_INTMEM);
        }

        grq = &pdev->toe_info.grqs[idx];
        if (!d_list_is_empty(&grq->aux_gen_list)) {
            mm_tcp_return_list_of_gen_bufs(pdev, &grq->aux_gen_list, 0, NON_EXISTENT_SB_IDX);
            d_list_clear(&grq->aux_gen_list);
        }
        if (!d_list_is_empty(&grq->active_gen_list)) {
            mm_tcp_return_list_of_gen_bufs(pdev, &grq->active_gen_list, 0, NON_EXISTENT_SB_IDX);
            d_list_clear(&grq->active_gen_list);
            lm_bd_chain_reset(pdev, &grq->bd_chain);
        }
    }
}

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
                              u32_t table_size, u8_t  enable)
{
    struct toe_rss_update_ramrod_data *data = pdev->toe_info.rss_update_data;
    lm_status_t lm_status   = LM_STATUS_SUCCESS;
    u8_t        value       = 0;
    u8_t        send_ramrod = 0;
    u8_t        rss_idx     = 0;
    u16_t       bitmap      = 0;
    u8_t        i,j;

    /* If data is NULL (allocation failed...) we don't want to fail this operation for L2 */
    if (pdev->params.l4_enable_rss == L4_RSS_DISABLED || data == NULL)
    {
        return LM_STATUS_SUCCESS;
    }

    DbgBreakIf(pdev->params.l4_enable_rss != L4_RSS_DYNAMIC);

    if (enable)
    {
        if (pdev->params.l4_grq_page_cnt > 2)
        {
            LM_TOE_FOREACH_RSS_IDX(pdev, rss_idx)
            {
                pdev->toe_info.grqs[rss_idx].high_bds_threshold = 2 * 512;
            }
        }
    }
    else
    {
        pdev->toe_info.grqs[LM_TOE_BASE_RSS_ID(pdev)].high_bds_threshold = 0;
    }


    for (j = 0; j < TOE_INDIRECTION_TABLE_SIZE/table_size; j++)
    {
        for (i = 0; i < table_size; i++)
        {
            value = LM_TOE_FW_RSS_ID(pdev,chain_indirection_table[i]);

            if (pdev->toe_info.indirection_table[(j*table_size)+i] != value) {
                pdev->toe_info.indirection_table[(j*table_size)+i] = value;
                send_ramrod = TRUE;
            }
        }
    }

    /* send update ramrod */
    if (send_ramrod)
    {
        pdev->params.update_comp_cnt = 0;
        pdev->params.update_suspend_cnt = 0;
        pdev->params.update_toe_comp_cnt = 0; /* We need a separate one for TOE to determine when to update sq credit */

        /* 2 global update counters :
         * update_comp_cnt -    Set initialy to the number of expected completions, decrmented every time an update completion is processed.
         *                      The processing for all chains is suspended until this counter gets to 0.
         * update_suspend_cnt - Set initialy to the number of potentially suspended chains. Decremented when each chain resumes processing. The ramrod completion
         *                      is indicated back only when this counter gets to 0.
         *
         * The update ramrod is 1 pending so we can access the completion and suspend counters here and below without grabbing a lock
         */

        /* Update once for Eth... */
        pdev->params.update_comp_cnt++;
        pdev->params.update_suspend_cnt++;


        /* TODO: Enhancment, send only on the chains that take part, and the ones removed... */
        LM_TOE_FOREACH_RSS_IDX(pdev, rss_idx)
        {
            bitmap |= (1<<LM_TOE_FW_RSS_ID(pdev,rss_idx));
        }

        mm_memcpy(data->indirection_table, pdev->toe_info.indirection_table, sizeof(data->indirection_table));
        data->toe_rss_bitmap = bitmap;

        pdev->params.update_comp_cnt += pdev->params.l4_rss_chain_cnt;
        pdev->params.update_suspend_cnt += pdev->params.l4_rss_chain_cnt;
        pdev->params.update_toe_comp_cnt = pdev->params.l4_rss_chain_cnt; /* TOE only! */

        lm_status = lm_command_post(pdev,
                                    LM_TOE_FW_RSS_ID(pdev, LM_TOE_BASE_RSS_ID(pdev)),
                                    RAMROD_OPCODE_TOE_RSS_UPDATE,
                                    CMD_PRIORITY_MEDIUM,
                                    TOE_CONNECTION_TYPE,
                                    pdev->toe_info.rss_update_data_phys.as_u64);

        if (lm_status == LM_STATUS_SUCCESS)
        {
            lm_status = LM_STATUS_PENDING;
        }
    }

    return lm_status;
}


/** Description
 *  function is called whenever the UM allocates more generic buffers
 */
void lm_tcp_rx_gen_bufs_alloc_cb(lm_device_t * pdev)
{
   u8_t i;

   LM_TOE_FOREACH_RSS_IDX(pdev, i)
   {

        lm_tcp_grq_t *grq = &pdev->toe_info.grqs[i];
        MM_ACQUIRE_TOE_GRQ_LOCK(pdev, i);
        if (grq->grq_compensate_on_alloc) {
            /* fill GRQ */
            if (lm_tcp_rx_fill_grq(pdev, i, NULL, FILL_GRQ_LOW_THRESHOLD)) {
                DbgMessage(pdev, INFORMl4rx, "lm_toe_service_rx_intr: Updating GRQ producer\n");
                /* notify the fw of the prod of the GRQ */
                LM_INTMEM_WRITE16(pdev, USTORM_TOE_GRQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,i), PORT_ID(pdev)),
                                  lm_bd_chain_prod_idx(&pdev->toe_info.grqs[i].bd_chain), BAR_USTRORM_INTMEM);
            }
        }
        MM_RELEASE_TOE_GRQ_LOCK(pdev, i);
    }
}

void lm_tcp_update_isles_cnts(struct _lm_device_t * pdev, s16_t number_of_isles, s32_t number_of_gen_bufs)
{
    lm_toe_isles_t  *archipelago = &pdev->toe_info.archipelago;

    pdev->toe_info.archipelago.number_of_isles += number_of_isles;
    pdev->toe_info.archipelago.gen_bufs_in_isles += number_of_gen_bufs;
    if (archipelago->number_of_isles > archipelago->max_number_of_isles) {
        archipelago->max_number_of_isles = archipelago->number_of_isles;
    }

    if (archipelago->gen_bufs_in_isles > archipelago->max_gen_bufs_in_isles) {
        archipelago->max_gen_bufs_in_isles = archipelago->gen_bufs_in_isles;
    }
    if (pdev->params.l4_max_gen_bufs_in_archipelago
            && (archipelago->gen_bufs_in_isles > (s32_t)pdev->params.l4_max_gen_bufs_in_archipelago)) {
        if (pdev->params.l4_limit_isles & L4_LI_NOTIFY) {
            DbgBreak();
        }
        if (pdev->params.l4_limit_isles & L4_LI_MAX_GEN_BUFS_IN_ARCHIPELAGO) {
            pdev->toe_info.archipelago.l4_decrease_archipelago = TRUE;
        }
    } else if (pdev->toe_info.archipelago.l4_decrease_archipelago) {
        if (archipelago->gen_bufs_in_isles <= (s32_t)pdev->params.l4_valid_gen_bufs_in_archipelago) {
            pdev->toe_info.archipelago.l4_decrease_archipelago = FALSE;
        }
    }

}

void lm_tcp_init_num_of_blocks_per_connection(
    struct _lm_device_t *pdev,
    u8_t    num)
{
    pdev->params.l4_num_of_blocks_per_connection = num;
}

u8_t lm_tcp_get_num_of_blocks_per_connection(
    struct _lm_device_t *pdev)
{
    return pdev->params.l4_num_of_blocks_per_connection;
}

lm_neigh_state_t * lm_tcp_get_next_neigh(
    struct _lm_device_t *pdev,
    lm_neigh_state_t * neigh_state)
{
    if (neigh_state == NULL) {
        neigh_state = (lm_neigh_state_t *) d_list_peek_head(&pdev->toe_info.state_blk.neigh_list);
    } else {
        neigh_state = (lm_neigh_state_t *) d_list_next_entry(&neigh_state->hdr.link);
    }
    return neigh_state;
}

lm_path_state_t * lm_tcp_get_next_path(
    struct _lm_device_t *pdev,
    lm_neigh_state_t * neigh_state,
    lm_path_state_t * path_state)
{
    if (path_state == NULL) {
        path_state = (lm_path_state_t *) d_list_peek_head(&pdev->toe_info.state_blk.path_list);
    } else {
        path_state = (lm_path_state_t *) d_list_next_entry(&path_state->hdr.link);
    }

    if (neigh_state != NULL) {
        while(path_state)  {
            if (path_state->neigh == neigh_state) {
                return path_state;
            }
            path_state = (lm_path_state_t *) d_list_next_entry(&path_state->hdr.link);
        }
    }
    return path_state;
}

lm_tcp_state_t * lm_tcp_get_next_tcp(
    struct _lm_device_t *pdev,
    lm_tcp_state_t * tcp_state)
{
    if (tcp_state == NULL) {
        tcp_state = (lm_tcp_state_t *) d_list_peek_head(&pdev->toe_info.state_blk.tcp_list);
    } else {
        tcp_state = (lm_tcp_state_t *) d_list_next_entry(&tcp_state->hdr.link);
    }
    return tcp_state;
}

u8_t lm_tcp_get_src_ip_cam_byte(
    IN    struct _lm_device_t   * pdev,
    IN    lm_path_state_t        * path)
{
    u8_t src_ip_byte;

    DbgBreakIf(!(pdev && path));

    if (path->path_const.ip_version ==  IP_VERSION_IPV4) {
        src_ip_byte = path->path_const.u.ipv4.src_ip & 0x000000FF;
    } else {
        src_ip_byte = path->path_const.u.ipv6.src_ip[0] & 0x000000FF;
    }
    return src_ip_byte;
}

lm_tcp_state_t* lm_tcp_find_offloaded_tcp_tuple(struct _lm_device_t   * pdev, u8_t src_ip_byte, u8_t src_tcp_b, u8_t dst_tcp_b, lm_tcp_state_t * prev_tcp)
{
    lm_tcp_state_t *connection_found = NULL;
    lm_tcp_state_t *current_tcp = NULL;

    while ((current_tcp =  lm_tcp_get_next_tcp(pdev, prev_tcp))) {
        u8_t c_src_tcp_b;
        u8_t c_dst_tcp_b;
        prev_tcp = current_tcp;
        c_src_tcp_b = current_tcp->tcp_const.src_port & 0x00FF;
        c_dst_tcp_b = current_tcp->tcp_const.dst_port & 0x00FF;
        if ((c_src_tcp_b == src_tcp_b) && (c_dst_tcp_b == dst_tcp_b)) {
            if ((current_tcp->path == NULL) || (lm_tcp_get_src_ip_cam_byte(pdev,current_tcp->path) == src_ip_byte)) {
                connection_found = current_tcp;
                break;
            }
        }
    }

    return connection_found;
}

u8_t * lm_tcp_get_pattern(struct _lm_device_t * pdev,
                          lm_tcp_state_t * tcp,
                          u8_t  pattern_idx,
                          u32_t offset,
                          u32_t * pattern_size)
{
    offset = tcp->integrity_info.current_offset_in_pattern_buf[pattern_idx] + offset;
    offset = offset % pdev->toe_info.integrity_info.pattern_size;
    if (*pattern_size > (pdev->toe_info.integrity_info.pattern_buf_size - pdev->toe_info.integrity_info.pattern_size)) {
        *pattern_size = pdev->toe_info.integrity_info.pattern_buf_size - pdev->toe_info.integrity_info.pattern_size;
    }
    return (pdev->toe_info.integrity_info.pattern_buf + offset);
}

void lm_tcp_set_pattern_offset(struct _lm_device_t * pdev,
                          lm_tcp_state_t * tcp,
                          u8_t  pattern_idx,
                          u32_t offset)
{
    tcp->integrity_info.current_offset_in_pattern_buf[pattern_idx] += offset;
    tcp->integrity_info.current_offset_in_pattern_buf[pattern_idx] =
        tcp->integrity_info.current_offset_in_pattern_buf[pattern_idx] % pdev->toe_info.integrity_info.pattern_size;

    return;
}

u32_t lm_tcp_find_pattern_offset(struct _lm_device_t * pdev, u8_t * sub_buf, u32_t sub_buf_size)
{
    u32_t i,j;
    for (j = 0; j < pdev->toe_info.integrity_info.pattern_size; j++) {
        for (i = 0; i < sub_buf_size; i++) {
            if (sub_buf[i] != pdev->toe_info.integrity_info.pattern_buf[j+i]) {
                break;
            }
        }
        if (i == sub_buf_size) {
            return j;
        }
    }
    return 0xFFFFFFFF;
}
