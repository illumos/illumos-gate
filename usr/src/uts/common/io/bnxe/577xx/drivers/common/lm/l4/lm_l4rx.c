
#include "lm5710.h"
#include "bd_chain.h"
#include "command.h"
#include "context.h"
#include "lm_l4fp.h"
#include "lm_l4sp.h"
#include "mm_l4if.h"
#include "mm.h"

/* The maximum counter value for consumed count, if it exceeds this value we post it to firmware. 
 * FW holds 32bits for this counter. Therefore 100MB is OK (see L4 VBD spec) */ 
#define MAX_GRQ_COUNTER               0x6400000
#define IS_OOO_CQE(__cmd)   ((__cmd == CMP_OPCODE_TOE_GNI) \
                          || (__cmd == CMP_OPCODE_TOE_GAIR) \
                          || (__cmd == CMP_OPCODE_TOE_GAIL) \
                          || (__cmd == CMP_OPCODE_TOE_GRI) \
                          || (__cmd == CMP_OPCODE_TOE_GJ) \
                          || (__cmd == CMP_OPCODE_TOE_DGI))

typedef struct toe_rx_bd toe_rx_bd_t;

static u16_t lm_squeeze_rx_buffer_list(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u16_t                 adjust_number,
    lm_tcp_gen_buf_t   ** unwanted_gen_buf
    );

static lm_status_t _lm_tcp_rx_post_buf(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_buffer_t     *tcp_buf,
    lm_frag_list_t      *frag_list
    );

static void lm_tcp_incr_consumed_gen(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t      * tcp,
    u32_t                 nbytes
    );

static void lm_tcp_return_gen_bufs(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t      * tcp, 
    lm_tcp_gen_buf_t    * gen_buf,
    u32_t                 flags,
    u8_t                  grq_idx
    );

static void lm_tcp_return_list_of_gen_bufs(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t      * tcp, 
    d_list_t            * gen_buf_list,
    u32_t                 flags,
    u8_t                  grq_idx
    );

static lm_isle_t * _lm_tcp_isle_get_free_list(
    struct _lm_device_t * pdev,
    u8_t                  grq_idx)
{
    lm_isle_t * free_list = NULL;
    lm_isle_t * isles_pool = pdev->toe_info.grqs[grq_idx].isles_pool;
    u32_t   isle_pool_idx;
    u32_t   isle_pool_size = pdev->params.l4_isles_pool_size; 
    DbgBreakIf(!isles_pool);
    for (isle_pool_idx = 0; isle_pool_idx < isle_pool_size; isle_pool_idx++) {
        if ((isles_pool[isle_pool_idx].isle_link.next == NULL) && (isles_pool[isle_pool_idx].isle_link.prev == NULL)) {
            free_list = isles_pool + isle_pool_idx;
            break;
        }
    }
    DbgBreakIf(!free_list);
    return free_list;
}

static lm_isle_t *  _lm_tcp_isle_find(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u8_t                  num_isle)
{
    lm_isle_t * isle = NULL;
    lm_tcp_con_rx_gen_info_t * gen_info;
    u8_t        isle_cnt, isle_idx;
    
    DbgBreakIf(!(tcp && tcp->rx_con));
    gen_info = &tcp->rx_con->u.rx.gen_info;
    isle_cnt = (u8_t)d_list_entry_cnt(&gen_info->isles_list);
    DbgBreakIf(!isle_cnt);
    DbgBreakIf(num_isle > isle_cnt);
    if (num_isle == gen_info->current_isle_number) {
        isle = gen_info->current_isle;
    } else {
        isle = (lm_isle_t*)gen_info->isles_list.head;
        for (isle_idx = 1; isle_idx < num_isle; isle_idx++) {
            isle = (lm_isle_t*)d_list_next_entry(&isle->isle_link);
        }
        gen_info->current_isle_number = num_isle;
        gen_info->current_isle = isle;
    }
    return isle;
}

static u32_t _lm_tcp_isle_remove(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u8_t                  grq_idx,
    u8_t                  num_isle,
    d_list_t            * gen_buf_list)
{
    u32_t       nbytes = 0;
    lm_isle_t * new_current_isle = NULL;
    lm_isle_t * isle = NULL;
    lm_tcp_con_rx_gen_info_t * gen_info;
    u8_t        isles_cnt;
    u8_t        new_current_isle_num;

    DbgBreakIf(!(tcp && tcp->rx_con));
    gen_info = &tcp->rx_con->u.rx.gen_info;
    isles_cnt = (u8_t)d_list_entry_cnt(&gen_info->isles_list);
    DbgBreakIf(!(num_isle && (num_isle <= isles_cnt)));
    isle = _lm_tcp_isle_find(pdev,tcp,num_isle);

//    DbgBreakIf((isles_cnt > 1) && (num_isle == 1));
    if (isle->isle_link.next != NULL) {
        new_current_isle = (lm_isle_t*)isle->isle_link.next;
        new_current_isle_num = num_isle;
    } else if (isle->isle_link.prev != NULL) {
        new_current_isle = (lm_isle_t*)isle->isle_link.prev;
        new_current_isle_num = num_isle - 1;
    } else {
        new_current_isle = NULL;
        new_current_isle_num = 0;
    }

#if defined(_NTDDK_)  
#pragma prefast (push)
#pragma prefast (disable:6011)
#endif //_NTDDK_
    d_list_remove_entry(&gen_info->isles_list, &isle->isle_link);
#if defined(_NTDDK_)  
#pragma prefast (pop)
#endif //_NTDDK_

    nbytes = isle->isle_nbytes;
    d_list_add_tail(gen_buf_list, &isle->isle_gen_bufs_list_head);
    d_list_init(&isle->isle_gen_bufs_list_head, NULL, NULL, 0);
    if (new_current_isle_num) {
        if (num_isle == 1) {
#if defined(_NTDDK_)  
#pragma prefast (push)
#pragma prefast (disable:28182)
#endif //_NTDDK_
            d_list_remove_entry(&gen_info->isles_list, &new_current_isle->isle_link);
#if defined(_NTDDK_)  
#pragma prefast (pop)
#endif //_NTDDK_
            d_list_add_tail(&isle->isle_gen_bufs_list_head, &new_current_isle->isle_gen_bufs_list_head);
            d_list_push_head(&gen_info->isles_list, &isle->isle_link);
            isle->isle_nbytes = new_current_isle->isle_nbytes;
#ifdef DEBUG_OOO_CQE
            isle->dedicated_cid = new_current_isle->dedicated_cid;
            isle->recent_ooo_combined_cqe  = new_current_isle->recent_ooo_combined_cqe;
#endif
            isle = new_current_isle;
            new_current_isle = &gen_info->first_isle;
        }
        mm_mem_zero(&isle->isle_gen_bufs_list_head, sizeof(lm_isle_t) - sizeof(d_list_entry_t));
        isle->isle_link.next = isle->isle_link.prev = NULL; 
    }
    gen_info->current_isle = new_current_isle;
    gen_info->current_isle_number = new_current_isle_num;
    return nbytes;
}

u32_t lm_tcp_rx_peninsula_to_rq(lm_device_t * pdev, lm_tcp_state_t * tcp, u32_t max_num_bytes_to_copy, u8_t sb_idx);

/* TODO: remove this temporary solution for solaris / linux compilation conflict, linux needs the
 * first option, solaris the latter */
#if defined(__LINUX)
#define TOE_RX_INIT_ZERO {{0}}
#else
#define TOE_RX_INIT_ZERO {0}
#endif

#define TOE_RX_DOORBELL(pdev,cid) do{\
    struct doorbell db = TOE_RX_INIT_ZERO;\
    db.header.data |= ((TOE_CONNECTION_TYPE << DOORBELL_HDR_T_CONN_TYPE_SHIFT) |\
                    (DOORBELL_HDR_T_RX << DOORBELL_HDR_T_RX_SHIFT));\
    DOORBELL((pdev), (cid), *((u32_t *)&db));\
    } while(0)

static __inline void lm_tcp_rx_write_db(
    lm_device_t *pdev,
    lm_tcp_state_t *tcp
    )
{
    lm_tcp_con_t *rx_con = tcp->rx_con;
    volatile struct toe_rx_db_data *db_data = rx_con->db_data.rx;
    
    if (!(rx_con->flags & TCP_RX_DB_BLOCKED)) {
        db_data->bds_prod += rx_con->db_more_bds;               /* nbds should be written before nbytes (FW assumption) */
        db_data->bytes_prod += rx_con->db_more_bytes;
                
        DbgMessage(pdev, INFORMl4rx,
                    "_lm_tcp_rx_write_db: cid=%d, (nbytes+=%d, nbds+=%d)\n",
                    tcp->cid, rx_con->db_more_bytes, rx_con->db_more_bds);
        TOE_RX_DOORBELL(pdev, tcp->cid);
    }

    /* assert if the new addition will make the cyclic counter post_cnt smaller than comp_cnt */
    DbgBreakIf(S64_SUB(rx_con->bytes_post_cnt + rx_con->db_more_bytes, rx_con->bytes_comp_cnt) < 0);
    rx_con->bytes_post_cnt += rx_con->db_more_bytes;
    rx_con->buffer_post_cnt += rx_con->db_more_bufs;
    rx_con->db_more_bytes = rx_con->db_more_bds = rx_con->db_more_bufs = 0;
    rx_con->fp_db_cnt++;   
}

/** Description
 *  This function is used to increase the window-size. Window is increased in 3 cases:
 *  1. RQ-placed bytes
 *  2. GRQ-Indicated succesfully (short/long loop, doensn't matter)
 *  3. Window-update from NDIS (initial rcv window increased)
 *  4. This function also takes into account dwa: delayed window algorithm, and updates the
 *     data structures accordingly, however, not all window-updates are part of the dwa algorithm, 
 *     specifically, (3) therefore, we need to know if the update is dwa-aware or not. 
 */ 
void lm_tcp_rx_post_sws (
    lm_device_t    * pdev,
    lm_tcp_state_t * tcp,
    lm_tcp_con_t   * rx_con,
    u32_t            nbytes,
    u8_t             op
    )
{
    volatile struct toe_rx_db_data *db_data = rx_con->db_data.rx;
    s32_t diff_to_fw;

    switch (op)
    {
    case TCP_RX_POST_SWS_INC:
        /*DbgMessage(pdev, FATAL, "lm_tcp_rx_post_sws() INC: OLD drv_rcv_win_right_edge=%d, nbytes=%d, NEW drv_rcv_win_right_edge=%d FW right_edge=%d \n", rx_con->u.rx.sws_info.drv_rcv_win_right_edge, nbytes, rx_con->u.rx.sws_info.drv_rcv_win_right_edge + nbytes, db_data->rcv_win_right_edge);*/
        if (rx_con->u.rx.sws_info.extra_bytes > nbytes) {
            rx_con->u.rx.sws_info.extra_bytes -= nbytes;
            nbytes = 0;
        } else {
            nbytes -= rx_con->u.rx.sws_info.extra_bytes;
            rx_con->u.rx.sws_info.extra_bytes = 0;
            rx_con->u.rx.sws_info.drv_rcv_win_right_edge += nbytes;
            if (rx_con->u.rx.sws_info.drv_rcv_win_right_edge >= db_data->rcv_win_right_edge) {
                  RESET_FLAGS(tcp->rx_con->db_data.rx->flags, TOE_RX_DB_DATA_IGNORE_WND_UPDATES);
            }
        }
        break;
    case TCP_RX_POST_SWS_DEC:
        if (rx_con->u.rx.sws_info.extra_bytes) {
            rx_con->u.rx.sws_info.extra_bytes += nbytes;
            nbytes = 0;
        }
        /*DbgMessage(pdev, FATAL, "lm_tcp_rx_post_sws() DEC: OLD drv_rcv_win_right_edge=%d, nbytes=%d, NEW drv_rcv_win_right_edge=%d\n", rx_con->u.rx.sws_info.drv_rcv_win_right_edge, nbytes, rx_con->u.rx.sws_info.drv_rcv_win_right_edge - nbytes);*/
        rx_con->u.rx.sws_info.drv_rcv_win_right_edge -= nbytes;
        SET_FLAGS(db_data->flags, TOE_RX_DB_DATA_IGNORE_WND_UPDATES);
        break;
    case TCP_RX_POST_SWS_SET:
        /*DbgMessage(pdev, FATAL, "lm_tcp_rx_post_sws() SET: nbytes=%d\n", nbytes);*/
        db_data->rcv_win_right_edge = nbytes;
        rx_con->u.rx.sws_info.extra_bytes = 0;;
        break;
    default:
        DbgBreakMsg("lm_tcp_rx_post_sws: Invalid operation\n");
        return;
    }

    /* note that diff_to_fw could be negative due to possibility of window-decrease in LH */
    diff_to_fw = S32_SUB(rx_con->u.rx.sws_info.drv_rcv_win_right_edge, db_data->rcv_win_right_edge);

    /* If this update isn't dwa_aware, it's good to go... */

    //DbgMessage(pdev, WARNl4, "###lm_tcp_rx_post_sws cid=%d num_bytes=%d diff_to_fw=%d \n", tcp->cid, nbytes, diff_to_fw );
    /* we give the window only if diff_to_fw is larger than mss, which also means only in case it is negative... */
    if ( ((diff_to_fw >= (s32_t)rx_con->u.rx.sws_info.mss) ||
         (diff_to_fw >= (((s32_t)tcp->tcp_cached.initial_rcv_wnd) / 2)))) {
        if (rx_con->u.rx.sws_info.timer_on) {
            /* Vladz TBD: Cancel the timer */
            rx_con->u.rx.sws_info.timer_on = 0;
        }

        /* Ring the Advertise Window doorbell here */
        if (!(tcp->rx_con->flags & TCP_RX_DB_BLOCKED) && !(tcp->rx_con->flags & TCP_RX_POST_BLOCKED)) {
            db_data->rcv_win_right_edge = rx_con->u.rx.sws_info.drv_rcv_win_right_edge;            
            DbgMessage(pdev, INFORMl4rx,
                "_lm_tcp_adv_wnd_write_db: cid=%d, nbytes=%d\n",
                tcp->cid, diff_to_fw);
            TOE_RX_DOORBELL(pdev, tcp->cid);        
        }
    } else {
        if ( ! rx_con->u.rx.sws_info.timer_on ) {
            /* Vladz TBD: schedule the timer here */
            rx_con->u.rx.sws_info.timer_on = 1;
        }
    }
}

static __inline toe_rx_bd_t * _lm_tcp_rx_set_bd (
    IN   lm_frag_t         * frag,
    IN   u16_t               flags,
    IN   lm_bd_chain_t     * rx_chain,
    IN   u32_t               dbg_bytes_prod /* Used for synchronizing between fw and driver rq-available-bytes
                                             * This is used only as a debug variable for asserting in the fw. */
    )
{
    struct toe_rx_bd * rx_bd;

    /* hw limit: each bd can point to a buffer with max size of 64KB */
    DbgBreakIf(frag->size > TCP_MAX_SGE_SIZE || frag->size == 0); 
    rx_bd = (struct toe_rx_bd *)lm_toe_bd_chain_produce_bd(rx_chain);
    rx_bd->addr_hi = frag->addr.as_u32.high;
    rx_bd->addr_lo = frag->addr.as_u32.low;
    rx_bd->flags = flags;
    rx_bd->size = (u16_t)frag->size;
    rx_bd->dbg_bytes_prod = dbg_bytes_prod;
    DbgMessage(NULL, VERBOSEl4rx, "Setting Rx BD flags=0x%x, bd_addr=0x%p, size=%d\n", rx_bd->flags, rx_bd, frag->size);
    return rx_bd;
}


/** Description
 *  function completes nbytes on a single tcp buffer and completes the buffer if it is
 *  completed. 
 * Assumptions:
 *   fp-lock is taken.
 *   It is only called from lm_tcp_rx_post_buf!!!
 */ 
static void lm_tcp_complete_tcp_buf(
    lm_device_t * pdev, lm_tcp_state_t * tcp, lm_tcp_con_t * con, lm_tcp_buffer_t * tcp_buf, u32_t completed_bytes)
{
    s_list_t completed_bufs;
    s_list_entry_t * entry;

    DbgBreakIf(completed_bytes > tcp_buf->more_to_comp);
    tcp_buf->more_to_comp -= completed_bytes;
    con->app_buf_bytes_acc_comp += completed_bytes;

    if(tcp_buf->more_to_comp == 0 &&  GET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_POST_END)) {
        tcp_buf->app_buf_xferred = con->app_buf_bytes_acc_comp;
        DbgBreakIf(tcp_buf->app_buf_xferred > tcp_buf->app_buf_size); /* this may be partial completion */
        con->app_buf_bytes_acc_comp = 0;
        if (GET_FLAGS(con->flags, TCP_POST_COMPLETE_SPLIT)) {
            RESET_FLAGS(con->flags, TCP_POST_COMPLETE_SPLIT);
        }
    } else {
        tcp_buf->app_buf_xferred = 0;
    }

    if (tcp_buf->more_to_comp == 0) {
        /* should have nothing in the active tb list except this buffer, if we're completing this buffer, 
         * it means that we had something in the peninsula, this means that at the end of the DPC there was
         * nothing in the active-tb-list, and between DPCs all posted buffers 'occupied' bytes from the peninsula
         * and were completed to the client. This means that there can be no RQ completions during the DPC that
         * will try to access the active tb list w/o a lock
         */ 
        DbgBreakIf(s_list_entry_cnt(&con->active_tb_list) != 1);
        lm_bd_chain_bds_consumed(&con->bd_chain, tcp_buf->bd_used);
    
        con->buffer_completed_cnt ++;
        DbgMessage(pdev, VERBOSEl4fp,
                    "cid=%d, completing tcp buf towards mm from post-flow, actual_completed_bytes=%d\n", 
                    tcp->cid, tcp_buf->size);    
        entry = s_list_pop_head(&con->active_tb_list);
        DbgBreakIf(con->rq_nbytes < tcp_buf->size);
        con->rq_nbytes -= tcp_buf->size;
        s_list_init(&completed_bufs, entry, entry, 1);
        con->rq_completion_calls++;
        mm_tcp_complete_bufs(pdev, tcp, con, &completed_bufs, LM_STATUS_SUCCESS);
    }
}



void lm_tcp_rx_cmp_process(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u32_t                 completed_bytes,
    u8_t                  push 
    )
{
    lm_tcp_con_t *rx_con;
    u32_t actual_bytes_completed;    
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_cmp_process, completed_bytes=%d, push=%d cid=%d\n", completed_bytes, push, tcp->cid);
    DbgBreakIf(!(completed_bytes || push)); /* otherwise there is no point for this function to be called */

    rx_con = tcp->rx_con;
    DbgBreakIf(! rx_con);

    if (!(rx_con->flags & TCP_DEFERRED_PROCESSING)) {
        mm_acquire_tcp_lock(pdev, rx_con);
    }
    DbgBreakIf(rx_con->flags & TCP_RX_COMP_BLOCKED);

    /* RQ completions can't arrive while we have something in the peninsula (peninsula must either be completed or copied
     * to the app-buffer before) An RQ_SKP within the dpc will always take care of previous RQs waiting to be copied to. */
    DbgBreakIf(!d_list_is_empty(&rx_con->u.rx.gen_info.peninsula_list)); 
    DbgBreakIf(!d_list_is_empty(&rx_con->u.rx.gen_info.dpc_peninsula_list)); 

    actual_bytes_completed = lm_tcp_complete_nbytes(pdev, tcp, rx_con, completed_bytes , push);       

    rx_con->bytes_comp_cnt += actual_bytes_completed;
    DbgBreakIf(S64_SUB(rx_con->bytes_post_cnt, rx_con->bytes_comp_cnt) < 0);
    DbgMessage(pdev, VERBOSEl4rx, "lm_tcp_rx_comp, after comp: pending=%d, active_bufs=%d\n",
                S64_SUB(rx_con->bytes_post_cnt, rx_con->bytes_comp_cnt), 
                s_list_entry_cnt(&rx_con->active_tb_list));

    if ( completed_bytes ) {
        /* Vladz: TBD
        lm_neigh_update_nic_reachability_time(tcp->path->neigh) */
    }
    if (!(rx_con->flags & TCP_DEFERRED_PROCESSING)) {
        mm_release_tcp_lock(pdev, rx_con);
    }
} /* lm_tcp_rx_comp */


void lm_tcp_rx_skp_process(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u32_t                 bytes_skipped,
    u8_t                  sb_idx
    )
{
    lm_tcp_con_t *rx_con;
    u32_t comp_bytes;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_skp_process, bytes_skipped=%d, cid=%d\n", bytes_skipped, tcp->cid);

    if (bytes_skipped == 0) {
        /* nothing to do here - occurs on special fw case, where there is GRQ->RQ processing with no GRQ and no RQ, 
         * this will usually happen at the beginning or in special cases of the connection */
        return;
    }

    rx_con = tcp->rx_con;
    DbgBreakIf(! rx_con);

    if (!GET_FLAGS(rx_con->flags, TCP_DEFERRED_PROCESSING)) {
        mm_acquire_tcp_lock(pdev, rx_con);
    }
    DbgBreakIf(GET_FLAGS(rx_con->flags, TCP_RX_COMP_BLOCKED));

    comp_bytes = min(bytes_skipped, tcp->rx_con->u.rx.skp_bytes_copied);
    if (comp_bytes) {
        tcp->rx_con->bytes_comp_cnt += comp_bytes;
        /* complete nbytes on buffers (dpc-flow ) */
        lm_tcp_complete_nbytes(pdev, tcp, tcp->rx_con, comp_bytes, /* push=*/ 0);
        bytes_skipped -= comp_bytes;
        tcp->rx_con->u.rx.skp_bytes_copied -= comp_bytes;
    }

    /* We know for sure, that all the application buffers we are about to access have already been posted
     * before the dpc, and therefore are valid in the active_tb_list.  
     * TBA Michals: bypass FW
     */
    if (bytes_skipped) {
        DbgBreakIf(!d_list_is_empty(&rx_con->u.rx.gen_info.peninsula_list)); 
        DbgBreakIfAll(d_list_is_empty(&rx_con->u.rx.gen_info.dpc_peninsula_list));
        DbgBreakIf(((lm_tcp_gen_buf_t *)d_list_peek_head(&rx_con->u.rx.gen_info.dpc_peninsula_list))->placed_bytes == 0);
        rx_con->u.rx.gen_info.bytes_copied_cnt_in_process += lm_tcp_rx_peninsula_to_rq(pdev, tcp, bytes_skipped,sb_idx);
    }

    if (!GET_FLAGS(rx_con->flags, TCP_DEFERRED_PROCESSING)) {
        mm_release_tcp_lock(pdev, rx_con);
    }
} /* lm_tcp_rx_skp */

void lm_tcp_rx_delete_isle(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u8_t                  sb_idx,
    u8_t                  num_isle,
    u32_t                 num_of_isles)
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    d_list_t                   removed_list;
    u32_t                      isle_nbytes;
    
  

    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_delete_isle cid=%d isle=%d\n", tcp->cid, num_isle);
    gen_info = &rx_con->u.rx.gen_info;
    d_list_init(&removed_list, NULL, NULL, 0);

    while (num_of_isles) {
        isle_nbytes = _lm_tcp_isle_remove(pdev, tcp, sb_idx, num_isle + (num_of_isles - 1), &removed_list);
        pdev->toe_info.grqs[sb_idx].number_of_isles_delta--;
        DbgBreakIf(isle_nbytes > gen_info->isle_nbytes);
        gen_info->isle_nbytes -= isle_nbytes;
        num_of_isles--;
    }

    pdev->toe_info.grqs[sb_idx].gen_bufs_in_isles_delta -= (s32_t)d_list_entry_cnt(&removed_list);
    if (!d_list_is_empty(&removed_list)) {
        lm_tcp_return_list_of_gen_bufs(pdev,tcp ,&removed_list, MM_TCP_RGB_COLLECT_GEN_BUFS, sb_idx);
        tcp->rx_con->droped_non_empty_isles++;
    } else {
        DbgBreak();
        tcp->rx_con->droped_empty_isles++;
    }
    rx_con->dpc_info.dpc_flags &= ~(LM_TCP_DPC_TOO_BIG_ISLE | LM_TCP_DPC_TOO_MANY_ISLES);    
    return;
}

u8_t lm_toe_is_rx_completion(lm_device_t *pdev, u8_t drv_toe_rss_id)
{
    u8_t result = FALSE;
    lm_tcp_rcq_t *rcq = NULL;

    DbgBreakIf(!(pdev && ARRSIZE(pdev->toe_info.rcqs) > drv_toe_rss_id));
    
    rcq = &pdev->toe_info.rcqs[drv_toe_rss_id];
    
    if ( rcq->hw_con_idx_ptr &&
        *rcq->hw_con_idx_ptr != lm_bd_chain_cons_idx(&rcq->bd_chain) )
    {
        result = TRUE;
    }
    DbgMessage(pdev, INFORMl4int, "lm_toe_is_rx_completion(): result is:%s\n", result? "TRUE" : "FALSE");

    return result;
}

/** Description
 *  checks if the processing of a certain RCQ is suspended
 */ 
u8_t lm_toe_is_rcq_suspended(lm_device_t *pdev, u8_t drv_toe_rss_id)
{
    u8_t result = FALSE;
    lm_tcp_rcq_t *rcq = NULL;

    if (drv_toe_rss_id < MAX_L4_RX_CHAIN)
    {
        rcq = &pdev->toe_info.rcqs[drv_toe_rss_id];
        if (rcq->suspend_processing) {
            result = TRUE;
	}
    }
    DbgMessage(pdev, INFORMl4int, "lm_toe_is_rcq_suspended(): sb_idx:%d, result is:%s\n", drv_toe_rss_id, result?"TRUE":"FALSE");
    return result;
}


/** Description
 *  Increment consumed generic counter for a connection.
 *  To avoid rollover in the FW if the counter exceeds a maximum threshold, the driver should 
 *  not wait for application buffers and post 'receive window update' doorbell immediately. 
 *  The FW holds 32bits for this counter. Therefore a threshold of 100MB is OK.
 */ 
static void lm_tcp_incr_consumed_gen(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t      * tcp,
    u32_t                 nbytes
    )
{
    volatile struct toe_rx_db_data *db_data = tcp->rx_con->db_data.rx;

    db_data->consumed_grq_bytes += nbytes;

    /* theres no need to increased the consumed_cnt in two stages (one in the driver and one for FW db_data)
     * we can always directly increase FW db_data, we need to decide whether we need to give a doorbell, basically
     * we have two cases where doorbells are given: (1) buffer posted and bypasses fw (2) indication succeeded in which case
     * window will also be increased, however, the window isn't always increased: if it's smaller than MSS, so, if we 
     * increase the consumed count by something smaller than mss - we'll give the doorbell here...   */

    if (nbytes < tcp->rx_con->u.rx.sws_info.mss) {
        if (!(tcp->rx_con->flags & TCP_RX_DB_BLOCKED)) {
            TOE_RX_DOORBELL(pdev, tcp->cid);        
        }
    }
}

/** Description
 *  Copies as many bytes as possible from the peninsula to the single tcp buffer received
 *  updates the peninsula.
 *  This function can be called from two flows: 
 *  1. Post of a buffer
 *  2. Completion of a dpc. 
 *  We need to know which flow it is called from to know which peninsula list to use: 
 *    dpc_peninsula_list / peninsula_list. 
 *  Post ALWAYS uses the peninsula_list, since it doesn't know about the dpc_peninsula
 *  Completion ALWAYS uses the dpc_peninsula_list, and in this case peninsula_list MUST be empty
 *  this is because there can be buffers in the active_tb_list ONLY if peninsula_list is empty.
 *  
 *  first_buf_offset refers to the peninsula we're dealing with, at the end of the dpc the dpc_peninsula
 *  is copied to the peninsula, therefore first_buf_offset will still be valid. copying from post means that
 *  there is something in the peninsula which means theres nothing in the active_tb_list ==> won't be a copy from
 *  dpc. Copying from dpc means theres something in the active-tb-list ==> nothing in the peninsula ==> won't be called
 *  from post, mutual exclusion exists between the post/dpc of copying, therefore we can have only one first_buffer_offset
 *  all other accesses (indication) are done under a lock. 
 * param: dpc - indicates if this is called from the dpc or not (post)
 * Assumptions:
 *  tcp_buf->more_to_comp is initialized
 *  tcp_buf->size         is initialized
 *  num_bufs_complete is initialized by caller (could differ from zero) 
 * Returns
 *  the actual number of bytes copied
 *  num_bufs_complete is the number of buffers that were completely copied to the pool and can be
 *  returned to the pool.
 */
static u32_t lm_tcp_rx_peninsula_to_rq_copy(
    lm_device_t     * pdev, 
    lm_tcp_state_t  * tcp, 
    lm_tcp_buffer_t * tcp_buf,
    d_list_t        * return_list,
    u32_t             max_num_bytes_to_copy,
    u8_t              dpc)
{
    lm_tcp_gen_buf_t         * curr_gen_buf;
    lm_tcp_con_rx_gen_info_t * gen_info;
    d_list_t                 * peninsula;
    u32_t                      tcp_offset;
    u32_t                      ncopy;
    u32_t                      bytes_left;
    u32_t                      bytes_copied = 0;

    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_peninsula_to_rq_copy tcp_buf = 0x%x cid=%d\n", *((u32_t *)&tcp_buf), tcp->cid);

    gen_info = &tcp->rx_con->u.rx.gen_info;

    if (dpc) {
        peninsula = &gen_info->dpc_peninsula_list;
    } else {
        peninsula = &gen_info->peninsula_list;
    }

    curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_head(peninsula);
    tcp_offset = tcp_buf->size - tcp_buf->more_to_comp;
    bytes_left = min(tcp_buf->more_to_comp, max_num_bytes_to_copy); /* copy to buffer only what's aloud...*/

    /* start copying as much as possible from peninsula to tcp buffer */
    while (bytes_left && curr_gen_buf && curr_gen_buf->placed_bytes) {
        ncopy = curr_gen_buf->placed_bytes - gen_info->first_buf_offset;
        if (ncopy > bytes_left) {
            ncopy = bytes_left;
        } 
        if (mm_tcp_copy_to_tcp_buf(pdev, tcp, tcp_buf, 
                                   curr_gen_buf->buf_virt + gen_info->first_buf_offset, /* start of data in generic buffer */
                                   tcp_offset, ncopy) != ncopy)
        {
            gen_info->copy_gen_buf_dmae_cnt++;

            /* If this is  generic buffer that has the free_when_done flag on it means it's non-cached memory and not physical
             * memory -> so, we can't try and dmae to it... not likely to happen... */
            if (!GET_FLAGS(curr_gen_buf->flags, GEN_FLAG_FREE_WHEN_DONE)) {
                if (mm_tcp_rx_peninsula_to_rq_copy_dmae(pdev,
                                                        tcp,
                                                        curr_gen_buf->buf_phys,
                                                        gen_info->first_buf_offset, /* start of data in generic buffer */
                                                        tcp_buf,
                                                        tcp_offset,
                                                        ncopy) != ncopy)
                {
                    DbgBreakMsg("Unable To Copy");
                    gen_info->copy_gen_buf_fail_cnt++;
    
                    break;
                }
             } else {
                    DbgBreakMsg("Unable To Copy");
                    gen_info->copy_gen_buf_fail_cnt++;
    
                    break;
             }
        }

        /* update peninsula */
        bytes_copied += ncopy;

        gen_info->first_buf_offset += (u16_t)ncopy;

        /* done with the generic buffer? - return it to the pool */
        if (curr_gen_buf->placed_bytes == gen_info->first_buf_offset) {
            curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_pop_head(peninsula);
            d_list_push_tail(return_list, &curr_gen_buf->link);
            gen_info->first_buf_offset = 0;
            gen_info->num_buffers_copied_grq++;
            curr_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_head(peninsula);
        } 

        /* update tcp buf stuff */
        bytes_left -= ncopy;
        tcp_offset += ncopy;
    }

    if (dpc) {
        gen_info->dpc_peninsula_nbytes -= bytes_copied;
    } else {
        gen_info->peninsula_nbytes -= bytes_copied;
    }
    
    /* return the number of bytes actually copied */
    return bytes_copied;
}

/** Description
 *  function copies data from the peninsula to tcp buffers already placed in the 
 *  active_tb_list. The function completes the buffers if a tcp buffer from active_tb_list 
 *  was partially/fully filled. This case simulates a call to lm_tcp_rx_comp
 *    (i.e. a completion received from firmware)
 * Assumptions:
 */
u32_t lm_tcp_rx_peninsula_to_rq(lm_device_t * pdev, lm_tcp_state_t * tcp, u32_t max_num_bytes_to_copy, u8_t sb_idx)
{
    lm_tcp_buffer_t          * curr_tcp_buf;
    lm_tcp_con_rx_gen_info_t * gen_info;
    d_list_t                   return_list;
    u32_t                      copied_bytes = 0, currently_copied = 0;

    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_peninsula_to_rq cid=%d\n", tcp->cid);
    
    gen_info     = &tcp->rx_con->u.rx.gen_info;

    DbgBreakIf(gen_info->peninsula_blocked == TRUE); /* terminate was already called - no copying should be done */

    /* Copy data from dpc_peninsula to tcp buffer[s] */
    d_list_init(&return_list, NULL, NULL, 0);

    curr_tcp_buf = lm_tcp_next_entry_dpc_active_list(tcp->rx_con);

    /* TBA Michals: FW Bypass First check if we can copy to bypass buffers */

    /* Copy the number of bytes received in SKP */
    while (max_num_bytes_to_copy && gen_info->dpc_peninsula_nbytes  && curr_tcp_buf) {
        currently_copied = lm_tcp_rx_peninsula_to_rq_copy(pdev, tcp, curr_tcp_buf, &return_list, max_num_bytes_to_copy, TRUE);
        curr_tcp_buf = (lm_tcp_buffer_t *)s_list_next_entry(&curr_tcp_buf->link);
        DbgBreakIf(max_num_bytes_to_copy < currently_copied);
        max_num_bytes_to_copy -= currently_copied;
        copied_bytes += currently_copied;
    }

    if (!d_list_is_empty(&return_list)) {

        lm_tcp_return_list_of_gen_bufs(pdev,tcp , &return_list,
                               (sb_idx != NON_EXISTENT_SB_IDX) ? MM_TCP_RGB_COLLECT_GEN_BUFS : 0, sb_idx);
    }
    
    /* If we've copied to a buffer in the active_tb_list we need to complete it since fw knows
     * the driver has the bytes and the driver will take care of copying them and completing them. 
     * this path simulates a call to lm_tcp_rx_comp (buffers taken from active_tb_list) */
    /* Note that pending bytes here could reach a negative value if a partial 
     * application buffer was posted and the doorbell hasn't been given yet, however, 
     * once the doorbell is given for the application buffer the pending bytes will reach a non-negative
     * value (>=0) */
    tcp->rx_con->bytes_comp_cnt += copied_bytes;
    /* complete nbytes on buffers (dpc-flow ) */
    lm_tcp_complete_nbytes(pdev, tcp, tcp->rx_con, copied_bytes, /* push=*/ 0);

    DbgMessage(pdev, VERBOSEl4rx, "lm_tcp_rx_peninsula_to_rq copied %d bytes cid=%d\n", copied_bytes, tcp->cid);
    return copied_bytes;
}

/** Description
 *  determines whether or not we can indicate.
 *  Rules: 
 *  - Indication is not blocked
 *  - we are not in the middle of completion a split-buffer 
 *     we can only indicate after an entire buffer has been completed/copied to.
 *     we determine this by the app_buf_bytes_acc_comp. This is to avoid the
 *     following data integrity race:
 *     application buffer: app_start, app_end
 *     app_start is posted, peninsula copied to app_start, app_start completed to
 *     fw then the rest is indicated. fw receives app_end, fw thinks peninsula was
 *     copied to buffer, application buffer misses data...
 *   - our active_tb_list is empty... we HAVE to make sure to
 *     always indicate after we've fully utilized our RQ
 *     buffers... 
 */ 
static __inline u8_t _lm_tcp_ok_to_indicate(lm_tcp_con_t * rx_con)
{
    return (!(rx_con->flags & TCP_RX_IND_BLOCKED) && (rx_con->app_buf_bytes_acc_comp == 0) && 
            (s_list_is_empty(&rx_con->active_tb_list)));
}

/** Description
 *  GA: add a buffer to the peninsula - nbytes represents the number of bytes in the previous buffer. 
 *  GR: release a buffer from the peninsula - nbytes represents the number of bytes in the current buffer.
 * Assumption:
 *  GR can only be called on a buffer that had been added using GA before
 */
void lm_tcp_rx_gen_peninsula_process(lm_device_t * pdev, lm_tcp_state_t * tcp, u32_t nbytes, lm_tcp_gen_buf_t * gen_buf)
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_tcp_gen_buf_t         * last_gen_buf;

    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_gen_peninsula_process, nbytes=%d, cid=%d add=%s\n", nbytes, tcp->cid,
                (gen_buf)? "TRUE"  : "FALSE");    

    DbgBreakIf(rx_con->flags & TCP_RX_COMP_BLOCKED);

    gen_info = &rx_con->u.rx.gen_info;

    /* update the previous buffer OR current buffer if this is a release operation. This function is always called
     * from within a DPC and updates the dpc_peninsula */
    if (nbytes) {
        gen_info->dpc_peninsula_nbytes += nbytes;
        last_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_tail(&gen_info->dpc_peninsula_list);
        DbgBreakIfAll(last_gen_buf == NULL);
        DbgBreakIfAll(last_gen_buf->placed_bytes != 0);
        DbgBreakIfAll(nbytes > LM_TCP_GEN_BUF_SIZE(pdev));
        last_gen_buf->placed_bytes = (u16_t)nbytes;
    } 

    if (gen_buf /* add */) {
        DbgBreakIf(SIG(gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
        DbgBreakIf(END_SIG(gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);
        
        d_list_push_tail(&gen_info->dpc_peninsula_list, &gen_buf->link);
    } 

}

void lm_tcp_rx_gen_isle_create(lm_device_t * pdev, lm_tcp_state_t * tcp, lm_tcp_gen_buf_t * gen_buf, u8_t sb_idx, u8_t isle_num)
{
    lm_isle_t                * current_isle = NULL;
    lm_isle_t                * next_isle = NULL;
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    u8_t                       isles_cnt;
    d_list_entry_t           * isle_entry_prev = NULL;
    d_list_entry_t           * isle_entry_next = NULL;

    gen_info = &rx_con->u.rx.gen_info;
    isles_cnt = (u8_t)d_list_entry_cnt(&gen_info->isles_list);
    if (isles_cnt) {
        DbgBreakIf(isles_cnt == T_TCP_MAX_ISLES_PER_CONNECTION_TOE);
        current_isle = _lm_tcp_isle_get_free_list(pdev, sb_idx);
        DbgBreakIf(!current_isle);
#ifdef DEBUG_OOO_CQE
        DbgBreakIf(current_isle->dedicated_cid != 0);
        current_isle->dedicated_cid = tcp->cid;
#endif
    } else {
        current_isle = &gen_info->first_isle;
    }

    d_list_push_head(&current_isle->isle_gen_bufs_list_head, &gen_buf->link);
    current_isle->isle_nbytes = 0;
    if (isle_num == 1) {
        if (current_isle != &gen_info->first_isle) {
            *current_isle = gen_info->first_isle;
            d_list_init(&gen_info->first_isle.isle_gen_bufs_list_head, NULL, NULL, 0);
            d_list_push_head(&gen_info->first_isle.isle_gen_bufs_list_head, &gen_buf->link);
            gen_info->first_isle.isle_nbytes = 0;
            isle_entry_prev = &gen_info->first_isle.isle_link;
            isle_entry_next = gen_info->first_isle.isle_link.next;
        }
    } else if (isle_num <= isles_cnt) {
        next_isle = _lm_tcp_isle_find(pdev,tcp,isle_num);
        isle_entry_prev = next_isle->isle_link.prev;
        isle_entry_next = &next_isle->isle_link;
    } else if (isle_num == (isles_cnt + 1)) {
        isle_entry_next = NULL;
        isle_entry_prev = gen_info->isles_list.tail;
    } else {
        DbgBreak();
    }

    d_list_insert_entry(&gen_info->isles_list, isle_entry_prev, isle_entry_next, &current_isle->isle_link);
    if (isle_num == 1) {
        current_isle = &gen_info->first_isle;
    }
#ifdef DEBUG_OOO_CQE
    SET_DEBUG_OOO_INFO(current_isle, CMP_OPCODE_TOE_GNI, 0);
#endif
    gen_info->current_isle = current_isle;
    gen_info->current_isle_number = isle_num;
    pdev->toe_info.grqs[sb_idx].number_of_isles_delta++;
    if (isles_cnt == gen_info->max_number_of_isles) {
        gen_info->max_number_of_isles++;
    }
}

void lm_tcp_rx_gen_isle_right_process(lm_device_t * pdev, lm_tcp_state_t * tcp, u32_t nbytes, lm_tcp_gen_buf_t * gen_buf, u8_t sb_idx, u8_t isle_num)
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_tcp_gen_buf_t         * last_gen_buf;
    lm_isle_t                * requested_isle;

    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_gen_isle_process nbytes = %d cid=%d\n", nbytes, tcp->cid);

    gen_info = &rx_con->u.rx.gen_info;
    requested_isle = _lm_tcp_isle_find(pdev,tcp,isle_num);
    DbgBreakIf(!requested_isle);

    /* update the previous buffer */
    last_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_tail(&requested_isle->isle_gen_bufs_list_head);
    DbgBreakIf(last_gen_buf == NULL);
    if (nbytes) {
        gen_info->isle_nbytes += nbytes;
        requested_isle->isle_nbytes += nbytes;
        DbgBreakIf(last_gen_buf->placed_bytes != 0);
        DbgBreakIf(nbytes > 0xffff);
        last_gen_buf->placed_bytes = (u16_t)nbytes;
    } else {
        DbgBreakIf(gen_buf == NULL);
        DbgBreakIf(last_gen_buf->placed_bytes == 0);
    }
    
    if (gen_buf) {
        DbgBreakIf(SIG(gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
        DbgBreakIf(END_SIG(gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);
        
        d_list_push_tail(&requested_isle->isle_gen_bufs_list_head, &gen_buf->link);
        pdev->toe_info.grqs[sb_idx].gen_bufs_in_isles_delta++;
        if (pdev->params.l4_max_gen_bufs_in_isle 
                && (d_list_entry_cnt(&requested_isle->isle_gen_bufs_list_head) > pdev->params.l4_max_gen_bufs_in_isle)) {
            if (pdev->params.l4_limit_isles & L4_LI_NOTIFY) {
                DbgBreak();
            }
            if (pdev->params.l4_limit_isles & L4_LI_MAX_GEN_BUFS_IN_ISLE) {
                rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_TOO_BIG_ISLE;
            }
        }
#ifdef DEBUG_OOO_CQE
        SET_DEBUG_OOO_INFO(requested_isle, CMP_OPCODE_TOE_GAIR, nbytes);
    } else {
        SET_DEBUG_OOO_INFO(requested_isle, CMP_OPCODE_TOE_GRI, nbytes);
#endif
    }
}

void lm_tcp_rx_gen_isle_left_process(lm_device_t * pdev, lm_tcp_state_t * tcp, u32_t nbytes, lm_tcp_gen_buf_t * gen_buf, u8_t sb_idx, u8_t isle_num)
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_tcp_gen_buf_t         * last_gen_buf;
    lm_isle_t                * requested_isle;

    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_gen_isle_process nbytes = %d cid=%d\n", nbytes, tcp->cid);

    gen_info = &rx_con->u.rx.gen_info;
    requested_isle = _lm_tcp_isle_find(pdev,tcp,isle_num);
    DbgBreakIf(!requested_isle);

    if (nbytes) {
        DbgBreakIf(!gen_info->wait_for_isle_left);
        DbgBreakIf(gen_buf != NULL);
        gen_info->wait_for_isle_left = FALSE;
        gen_info->isle_nbytes += nbytes;
        requested_isle->isle_nbytes += nbytes;
#if defined(_NTDDK_)  
#pragma prefast (push)
#pragma prefast (disable:28182) // If nbytes is larger that zero than ((returned_list_of_gen_bufs))->head is not NULL.
#endif //_NTDDK_
        last_gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_head(&requested_isle->isle_gen_bufs_list_head);
        DbgBreakIf(last_gen_buf->placed_bytes);
        last_gen_buf->placed_bytes = (u16_t)nbytes;
#if defined(_NTDDK_)  
#pragma prefast (pop)
#endif //_NTDDK_
    } else {
        DbgBreakIf(gen_info->wait_for_isle_left);
        DbgBreakIf(gen_buf == NULL);
        DbgBreakIf(SIG(gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
        DbgBreakIf(END_SIG(gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);
        gen_info->wait_for_isle_left = TRUE;
        d_list_push_head(&requested_isle->isle_gen_bufs_list_head, &gen_buf->link);
        pdev->toe_info.grqs[sb_idx].gen_bufs_in_isles_delta++;
    }
#ifdef DEBUG_OOO_CQE
    SET_DEBUG_OOO_INFO(requested_isle, CMP_OPCODE_TOE_GAIL, nbytes);
#endif
}

void lm_tcp_rx_gen_join_process(lm_device_t * pdev, lm_tcp_state_t * tcp, u8_t sb_idx, u8_t isle_num)
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_isle_t                * start_isle;
    d_list_t                   gen_buf_list;
    u32_t                      isle_nbytes;
    DbgMessage(pdev, VERBOSEl4rx, "##lm_tcp_rx_gen_join_process cid=%d\n", tcp->cid);

    gen_info = &rx_con->u.rx.gen_info;

    
    if (!isle_num) {
        /* break if peninsula list isn't empty and the last buffer in list isn't released yet */
        DbgBreakIf(d_list_entry_cnt(&gen_info->dpc_peninsula_list) && 
                   ((lm_tcp_gen_buf_t *)(d_list_peek_tail(&gen_info->dpc_peninsula_list)))->placed_bytes == 0);
        d_list_init(&gen_buf_list, NULL, NULL, 0);
        isle_nbytes = _lm_tcp_isle_remove(pdev, tcp, sb_idx, 1, &gen_buf_list);
//        DbgBreakIf(!(isle_nbytes && d_list_entry_cnt(&gen_buf_list)));
        if (d_list_entry_cnt(&gen_buf_list) > 1) {
            DbgBreakIf(((lm_tcp_gen_buf_t *)(d_list_peek_head(&gen_buf_list)))->placed_bytes == 0);
        }
        pdev->toe_info.grqs[sb_idx].gen_bufs_in_isles_delta -= (s32_t)d_list_entry_cnt(&gen_buf_list);
        pdev->toe_info.grqs[sb_idx].number_of_isles_delta--;
    
        if (!d_list_is_empty(&gen_buf_list)) {
        d_list_add_tail(&gen_info->dpc_peninsula_list, &gen_buf_list);
        }
        gen_info->dpc_peninsula_nbytes += isle_nbytes;
        gen_info->isle_nbytes -= isle_nbytes;
    } else {
        start_isle = _lm_tcp_isle_find(pdev,tcp,isle_num);
        d_list_init(&gen_buf_list, NULL, NULL, 0);
        isle_nbytes = _lm_tcp_isle_remove(pdev, tcp, sb_idx, isle_num + 1, &gen_buf_list);
//        DbgBreakIf(!(isle_nbytes && d_list_entry_cnt(&gen_buf_list)));
        pdev->toe_info.grqs[sb_idx].number_of_isles_delta--;
        if (d_list_entry_cnt(&gen_buf_list) > 1) {
            DbgBreakIf(((lm_tcp_gen_buf_t *)(d_list_peek_head(&gen_buf_list)))->placed_bytes == 0);
        }
        DbgBreakIf(((lm_tcp_gen_buf_t *)(d_list_peek_tail(&start_isle->isle_gen_bufs_list_head)))->placed_bytes == 0);
        if (!d_list_is_empty(&gen_buf_list)) {
        d_list_add_tail(&start_isle->isle_gen_bufs_list_head, &gen_buf_list);
        }
        start_isle->isle_nbytes += isle_nbytes;
#ifdef DEBUG_OOO_CQE
        SET_DEBUG_OOO_INFO(start_isle,CMP_OPCODE_TOE_GJ,0);
#endif
    }
    rx_con->dpc_info.dpc_flags &= ~(LM_TCP_DPC_TOO_BIG_ISLE | LM_TCP_DPC_TOO_MANY_ISLES);    

}

static __inline lm_tcp_gen_buf_t * lm_tcp_rx_next_grq_buf(lm_device_t * pdev, u8_t sb_idx)
{
    lm_tcp_gen_buf_t * gen_buf;

    /* 11/12/2008 - TODO: Enhance locking acquisition method,
     * TBD: aggragate cons, and active_gen_list updates */
    MM_ACQUIRE_TOE_GRQ_LOCK_DPC(pdev, sb_idx);

    /* Get the generic buffer for this completion */
    gen_buf = (lm_tcp_gen_buf_t *)d_list_pop_head(&pdev->toe_info.grqs[sb_idx].active_gen_list);
    if (ERR_IF(gen_buf == NULL)) {
        DbgBreakMsg("Received a fw GA/GAI without any generic buffers\n");
        return NULL;
    }
    DbgBreakIf(!gen_buf);
    DbgBreakIf(SIG(gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
    DbgBreakIf(END_SIG(gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);

    /* each generic buffer is represented by ONE bd on the bd-chain */
    lm_bd_chain_bds_consumed(&pdev->toe_info.grqs[sb_idx].bd_chain, 1);

    MM_RELEASE_TOE_GRQ_LOCK_DPC(pdev, sb_idx);

    return gen_buf;
}

/** Description
 *   completes the fast-path operations for a certain connection
 *  Assumption: 
 *   fp-rx lock is taken
 *   This function is mutual exclusive: there can only be one thread running it at a time.
 */ 
void lm_tcp_rx_complete_tcp_fp(lm_device_t * pdev, lm_tcp_state_t * tcp, lm_tcp_con_t * con)
{
    lm_tcp_buffer_t * curr_tcp_buf;
    u32_t add_sws_bytes = 0;

    if (con->dpc_info.dpc_comp_blocked) {
        /* we will no longer receive a "skp" */
        SET_FLAGS(con->flags, TCP_POST_NO_SKP); /* so that new posts complete immediately... */
        /* complete any outstanding skp bytes... */
        if (tcp->rx_con->u.rx.skp_bytes_copied) {
            /* now we can complete these bytes that have already been copied... */
            tcp->rx_con->bytes_comp_cnt += tcp->rx_con->u.rx.skp_bytes_copied;
            /* complete nbytes on buffers (dpc-flow ) */
            lm_tcp_complete_nbytes(pdev, tcp, tcp->rx_con, tcp->rx_con->u.rx.skp_bytes_copied, /* push=*/ 0);
            tcp->rx_con->u.rx.skp_bytes_copied = 0;
        }
    }

    /* TBA Michals FW BYPASS...copy here */
    if (!d_list_is_empty(&con->u.rx.gen_info.dpc_peninsula_list)) {
        /* only copy if this is the end... otherwise, we will wait for that SKP... */
        if (lm_tcp_next_entry_dpc_active_list(con) && con->u.rx.gen_info.dpc_peninsula_nbytes && con->dpc_info.dpc_comp_blocked) {
            /* couldn't have been posted buffers if peninsula exists... */
            DbgBreakIf(!d_list_is_empty(&con->u.rx.gen_info.peninsula_list)); 
            con->u.rx.gen_info.bytes_copied_cnt_in_comp += lm_tcp_rx_peninsula_to_rq(pdev, tcp, 0xffffffff,NON_EXISTENT_SB_IDX);
        }

        /* check if we still have something in the peninsula after the copying AND our active tb list is empty... otherwise, it's intended
         * for that and we'll wait for the next RQ_SKP in the next DPC. UNLESS, we've got completion block, in which case RQ_SKP won't make it
         * way ever... */
        curr_tcp_buf = lm_tcp_next_entry_dpc_active_list(con);
        DbgBreakIf(!d_list_is_empty(&con->u.rx.gen_info.dpc_peninsula_list) && curr_tcp_buf && con->dpc_info.dpc_comp_blocked);
        if (!d_list_is_empty(&con->u.rx.gen_info.dpc_peninsula_list) && !curr_tcp_buf) {
            d_list_add_tail(&con->u.rx.gen_info.peninsula_list, &con->u.rx.gen_info.dpc_peninsula_list);
            con->u.rx.gen_info.peninsula_nbytes += con->u.rx.gen_info.dpc_peninsula_nbytes;
            con->u.rx.gen_info.dpc_peninsula_nbytes = 0;

            /* we want to leave any non-released buffer in the dpc_peninsula (so that we don't access the list w/o a lock) */
            if (((lm_tcp_gen_buf_t *)d_list_peek_tail(&con->u.rx.gen_info.peninsula_list))->placed_bytes == 0) {
                lm_tcp_gen_buf_t * gen_buf;
                gen_buf = (lm_tcp_gen_buf_t *)d_list_pop_tail(&con->u.rx.gen_info.peninsula_list);
                if CHK_NULL(gen_buf)
                {
                    DbgBreakIfAll( !gen_buf ) ;
                    return;
                }
                d_list_init(&con->u.rx.gen_info.dpc_peninsula_list, &gen_buf->link, &gen_buf->link, 1);
            } else {
                d_list_clear(&con->u.rx.gen_info.dpc_peninsula_list);
            }

        }
    }
   
    /**** Client completing :  may result in lock-release *****/
    /* during lock-release, due to this function being called from service_deferred, more
     * cqes can be processed. We don't want to mix. This function is mutually exclusive, so 
     * any processing makes it's way to being completed by calling this function.
     * the following define a "fast-path completion"
     * (i)   RQ buffers to be completed
     *       defined by dpc_completed_tail and are collected during lm_tcp_complete_bufs BEFORE lock
     *       is released, so no more buffer processing can make it's way into this buffer completion.
     * (ii)  GRQ buffers to be indicated
     *       Are taken from peninsula, and not dpc_peninsula, so no NEW generic buffers can make their
     *       way to this indication
     * (iii) Fin to be indicated
     *       determined by the flags, since dpc_flags CAN be modified during processing we copy
     *       them to a snapshot_flags parameter, which is initialized in this function only, so no fin
     *       can can make its way in while we release the lock.
     * (iv)  Remainders for sp
     *       all sp operations are logged in dpc_flags. for the same reason as (iii) no sp commands can 
     *       make their way in during this fp-completion, all sp-processing after will relate to this point in time.
     */
    /* NDC is the only fp flag: determining that we should complete all the processed cqes. Therefore, we can 
     * turn it off here. We should turn it off, since if no sp flags are on, the sp-complete function shouldn't be called
     */
//    RESET_FLAGS(con->dpc_info.dpc_flags, LM_TCP_DPC_NDC);
    con->dpc_info.snapshot_flags = con->dpc_info.dpc_flags;
    con->dpc_info.dpc_flags = 0;

    /* compensate fw-window with the rq-placed bytes */
    if (con->dpc_info.dpc_rq_placed_bytes) {
        add_sws_bytes += con->dpc_info.dpc_rq_placed_bytes;
        con->dpc_info.dpc_rq_placed_bytes = 0;
    }
    

    /* check if we completed a buffer that as a result unblocks the um from posting more (a split buffer that
     * was placed on the last bd). If this occured - we should not have any other RQs!!! */
    if (con->dpc_info.dpc_unblock_post) {
        RESET_FLAGS(con->flags, TCP_POST_DELAYED);
        con->dpc_info.dpc_unblock_post = 0;
    }

    /* NOTE: AFTER THIS STAGE DO NOT ACCESS DPC-INFO ANYMORE - for deferred cqes issue */

    /* complete buffers to client */
    if (con->dpc_info.dpc_completed_tail != NULL) {
        lm_tcp_complete_bufs(pdev,tcp,con);
    }

    /* Is there something left to indicate? */
    if (!d_list_is_empty(&con->u.rx.gen_info.peninsula_list) && _lm_tcp_ok_to_indicate(con)) {
        mm_tcp_rx_indicate_gen(pdev,tcp);
        add_sws_bytes += tcp->rx_con->u.rx.gen_info.add_sws_bytes; /* any bytes we need to update will be aggregated here during indicate */
        tcp->rx_con->u.rx.gen_info.add_sws_bytes = 0;
    }    

    if (add_sws_bytes) {
        lm_tcp_rx_post_sws(pdev, tcp, con, add_sws_bytes, TCP_RX_POST_SWS_INC);
    }

}


/** Description
 *  processes a single cqe. 
 */ 
void lm_tcp_rx_process_cqe(
    lm_device_t       * pdev, 
    struct toe_rx_cqe * cqe, 
    lm_tcp_state_t    * tcp, 
    u8_t                sb_idx)
{
    u32_t   nbytes;
    u8_t    cmd;
    u8_t    isle_num = 0;

    cmd = ((cqe->params1 & TOE_RX_CQE_COMPLETION_OPCODE) >> TOE_RX_CQE_COMPLETION_OPCODE_SHIFT);
    

    /* Check that the cqe nbytes make sense, we could have got here by chance... */
    /* update completion has a different usage for nbyts which is a sequence -so any number is valid*/
    if(IS_OOO_CQE(cmd)) {
        nbytes = (cqe->data.ooo_params.ooo_params & TOE_RX_CQE_OOO_PARAMS_NBYTES) >> TOE_RX_CQE_OOO_PARAMS_NBYTES_SHIFT;
        isle_num = (cqe->data.ooo_params.ooo_params & TOE_RX_CQE_OOO_PARAMS_ISLE_NUM) >> TOE_RX_CQE_OOO_PARAMS_ISLE_NUM_SHIFT;
        if (((isle_num == 0) && (cmd != CMP_OPCODE_TOE_GJ)) || (isle_num > T_TCP_MAX_ISLES_PER_CONNECTION_TOE)) { 
            DbgMessage(pdev, FATAL, "Isle number %d is not valid for OOO CQE %d\n", isle_num, cmd);
            DbgBreak();
        }
    } else if (cmd == RAMROD_OPCODE_TOE_UPDATE) {
        nbytes = cqe->data.raw_data;
    } else {
        nbytes = (cqe->data.in_order_params.in_order_params & TOE_RX_CQE_IN_ORDER_PARAMS_NBYTES) >> TOE_RX_CQE_IN_ORDER_PARAMS_NBYTES_SHIFT;
        DbgBreakIfAll(nbytes & 0xc0000000); /* two upper bits on show a completion larger than 1GB - a bit odd...*/
        DbgBreakIf(nbytes && tcp->rx_con->dpc_info.dpc_comp_blocked);
    }
    if (pdev->toe_info.archipelago.l4_decrease_archipelago 
            && d_list_entry_cnt(&tcp->rx_con->u.rx.gen_info.first_isle.isle_gen_bufs_list_head)) {
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_TOO_MANY_ISLES;
    }
    switch(cmd) 
    {
    case CMP_OPCODE_TOE_SRC_ERR:
        DbgMessage(pdev, FATAL, "ERROR: NO SEARCHER ENTRY!\n");
        DbgBreakIfAll(TRUE);
        return;
    case CMP_OPCODE_TOE_GA:
        //DbgMessage(pdev, WARN, "GenericAdd cid=%d nbytes=%d!\n", tcp->cid, cqe->nbytes);
        lm_tcp_rx_gen_peninsula_process(pdev, tcp, nbytes, 
                                        lm_tcp_rx_next_grq_buf(pdev, sb_idx));
        return;
    case CMP_OPCODE_TOE_GNI:
        //DbgMessage(pdev, WARN, "GenericCreateIsle cid=%d isle_num=%d!\n", tcp->cid, isle_num);
        DbgBreakIf(nbytes);
        lm_tcp_rx_gen_isle_create(pdev, tcp, 
                                  lm_tcp_rx_next_grq_buf(pdev, sb_idx), sb_idx, isle_num);
        return;
    case CMP_OPCODE_TOE_GAIR:
        //DbgMessage(pdev, WARN, "GenericAddIsleR cid=%d isle_num=%d nbytes=%d!\n", tcp->cid, isle_num, nbytes);
        lm_tcp_rx_gen_isle_right_process(pdev, tcp, nbytes, 
                                   lm_tcp_rx_next_grq_buf(pdev, sb_idx), sb_idx, isle_num);
        return;
    case CMP_OPCODE_TOE_GAIL:
        DbgMessage(pdev, WARN, "GenericAddIsleL cid=%d isle_num=%d nbytes=%d!\n", tcp->cid, isle_num, nbytes);
        if (nbytes) 
        {
            lm_tcp_rx_gen_isle_left_process(pdev, tcp, nbytes,
                                       NULL, sb_idx, isle_num);
        } 
        else 
        {
            lm_tcp_rx_gen_isle_left_process(pdev, tcp, 0,
                                       lm_tcp_rx_next_grq_buf(pdev, sb_idx), sb_idx, isle_num);
        }
        return;
    case CMP_OPCODE_TOE_GRI:
//        DbgMessage(pdev, WARN, "GenericReleaseIsle cid=%d isle_num=%d nbytes=%d!\n", tcp->cid, isle_num, nbytes);
        lm_tcp_rx_gen_isle_right_process(pdev, tcp, nbytes, NULL, sb_idx, isle_num);
        return;
    case CMP_OPCODE_TOE_GR:
        //DbgMessage(pdev, WARN, "GenericRelease cid=%d nbytes=%d!\n", tcp->cid, cqe->nbytes);
        lm_tcp_rx_gen_peninsula_process(pdev, tcp, nbytes, NULL); 
        return;
    case CMP_OPCODE_TOE_GJ:
        //DbgMessage(pdev, WARN, "GenericJoin cid=%d nbytes=%d!\n", tcp->cid, cqe->nbytes);
        lm_tcp_rx_gen_join_process(pdev, tcp, sb_idx, isle_num);
        return;
    case CMP_OPCODE_TOE_CMP:
        //DbgMessage(pdev, WARN, "Cmp(push) cid=%d nbytes=%d!\n", tcp->cid, cqe->nbytes);
        /* Add fast path handler here */
        lm_tcp_rx_cmp_process(pdev, tcp, nbytes, 1);
        return;
    case CMP_OPCODE_TOE_REL:
        //DbgMessage(pdev, WARN, "Rel(nopush) cid=%d nbytes=%d!\n", tcp->cid, cqe->nbytes);
        lm_tcp_rx_cmp_process(pdev, tcp, nbytes, 0);
        return;
	case CMP_OPCODE_TOE_SKP:
        //DbgMessage(pdev, WARN, "Skp cid=%d nbytes=%d!\n", tcp->cid, cqe->nbytes);
        lm_tcp_rx_skp_process(pdev, tcp, nbytes, sb_idx);
        return;
    case CMP_OPCODE_TOE_DGI:
        DbgMessage(pdev, WARN, "Delete Isle cid=%d!\n", tcp->cid);
        lm_tcp_rx_delete_isle(pdev, tcp, sb_idx, isle_num, nbytes);
        return;
    }

    /* for the rest of the commands, if we have nbytes, we need to complete them (generic/app) */
    /* unless it's an update completion, in which case the nbytes has a different meaning. */
    if ((cmd != RAMROD_OPCODE_TOE_UPDATE) && nbytes) {
        lm_tcp_gen_buf_t * gen_buf;
        gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_tail(&tcp->rx_con->u.rx.gen_info.dpc_peninsula_list);
        if(gen_buf && (gen_buf->placed_bytes == 0)) {            
            lm_tcp_rx_gen_peninsula_process(pdev, tcp, nbytes, NULL);        
        } else {
            /* if we're here - we will no longer see a RQ_SKP so, let's simulate one...note if we didn't get nbytes here.. we still need
             * to take care of this later if it's a blocking completion the skip will have to be everything in the peninsula
            * we can access skp_bytes here lockless, because the only time it will be accessed in post is if there is something in the peninsula, if we got a RQ_SKP here, there can't be...*/
            DbgBreakIf(!d_list_is_empty(&tcp->rx_con->u.rx.gen_info.peninsula_list));
            DbgBreakIf(tcp->rx_con->rq_nbytes <= tcp->rx_con->u.rx.gen_info.dpc_peninsula_nbytes+tcp->rx_con->u.rx.skp_bytes_copied); // we got a  RQ completion here... so peninsula CAN;T cover RQ!!!
            lm_tcp_rx_skp_process(pdev, tcp, tcp->rx_con->u.rx.gen_info.dpc_peninsula_nbytes+tcp->rx_con->u.rx.skp_bytes_copied, sb_idx);

            /* We give push=1 here, this will seperate between 'received' data and 'aborted' bufs. we won't
             * have any buffers left that need to be aborted that have partial completed data on them  */
            lm_tcp_rx_cmp_process(pdev, tcp, nbytes, 2 /* push as result of sp-completion*/);
        }
    }

    switch (cmd) {
    case CMP_OPCODE_TOE_FIN_RCV:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_FIN_RECV;
        tcp->rx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_REMOTE_FIN_RECEIVED */
        return;
    case CMP_OPCODE_TOE_FIN_UPL:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_FIN_RECV_UPL;
        tcp->rx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_REMOTE_FIN_RECEIVED + Request to upload the connection */
        return;
    case CMP_OPCODE_TOE_RST_RCV:         
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RESET_RECV;
        tcp->rx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_REMOTE_RST_RECEIVED */
        return;
    case RAMROD_OPCODE_TOE_UPDATE:
        DbgBreakIf( (tcp->hdr.status != STATE_STATUS_NORMAL) && (tcp->hdr.status != STATE_STATUS_ABORTED));
        DbgBreakIf(tcp->sp_request == NULL);
        DbgBreakIf((tcp->sp_request->type != SP_REQUEST_UPDATE_NEIGH) &&
                   (tcp->sp_request->type != SP_REQUEST_UPDATE_PATH) &&
                   (tcp->sp_request->type != SP_REQUEST_UPDATE_TCP) &&
                   (tcp->sp_request->type != SP_REQUEST_UPDATE_PATH_RELINK));
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;

        /*DbgMessage(pdev, FATAL, "lm_tcp_rx_process_cqe() RAMROD_OPCODE_TOE_UPDATE: IGNORE_WND_UPDATES=%d, cqe->nbytes=%d\n", GET_FLAGS(tcp->rx_con->db_data.rx->flags, TOE_RX_DB_DATA_IGNORE_WND_UPDATES), cqe->nbytes);*/

        if ((tcp->sp_request->type == SP_REQUEST_UPDATE_TCP) && (GET_FLAGS(tcp->rx_con->db_data.rx->flags, TOE_RX_DB_DATA_IGNORE_WND_UPDATES)))
        {
            tcp->rx_con->dpc_info.dpc_fw_wnd_after_dec = nbytes;
        }
        return;
    case CMP_OPCODE_TOE_URG:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_URG;
        return;
    case CMP_OPCODE_TOE_MAX_RT:
        DbgMessage(pdev, WARNl4, "lm_tcp_rx_process_cqe: CMP_OPCODE_TOE_MAX_RT cid=%d\n", tcp->cid);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RT_TO;
        return;
    case CMP_OPCODE_TOE_RT_TO:
        DbgMessage(pdev, WARNl4, "lm_tcp_rx_process_cqe: CMP_OPCODE_TOE_RT_TO cid=%d\n", tcp->cid);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RT_TO;
        return;
    case CMP_OPCODE_TOE_KA_TO:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_KA_TO;
        return;
    case CMP_OPCODE_TOE_DBT_RE:
        /* LH Inbox specification:  Black Hole detection (RFC 2923)
         * TCP Chimney target MUST upload the connection if the TCPDoubtReachabilityRetransmissions threshold is hit.
         * SPARTA test scripts and tests that will fail if not implemented: All tests in Tcp_BlackholeDetection.wsf, we cause
         * the upload by giving L4_UPLOAD_REASON_UPLOAD_REQUEST (same as Teton) */
        DbgMessage(pdev, INFORMl4, "lm_tcp_rx_process_cqe: RCQE CMP_OPCODE_TOE_DBT_RE, cid=%d\n", tcp->cid);
        DbgMessage(pdev, WARNl4, "lm_tcp_rx_process_cqe: RCQE CMP_OPCODE_TOE_DBT_RE, cid=%d IGNORING!!!\n", tcp->cid);
        /* We add this here only for windows and not ediag */
        #if (!defined(DOS)) && (!defined(__LINUX))
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_DBT_RE;
        #endif
        return;
    case CMP_OPCODE_TOE_SYN:
    case CMP_OPCODE_TOE_FW2_TO:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_UPLD_CLOSE;
        return;
    case CMP_OPCODE_TOE_2WY_CLS:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_UPLD_CLOSE;
        return;
    case CMP_OPCODE_TOE_OPT_ERR:
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_OPT_ERR;
        return;
    case RAMROD_OPCODE_TOE_QUERY:
        DbgBreakIf(! tcp->sp_request );
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_QUERY);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        return;
    case RAMROD_OPCODE_TOE_SEARCHER_DELETE:
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_TERMINATE_OFFLOAD);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        return;
    case RAMROD_OPCODE_TOE_RESET_SEND:
        DbgBreakIf(! tcp->sp_request);
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_ABORTIVE_DISCONNECT);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        tcp->rx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_RST_REQ_COMPLETED */
        return;
    case RAMROD_OPCODE_TOE_INVALIDATE:
        DbgBreakIf(! tcp->sp_request);
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_INVALIDATE);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        tcp->rx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_INV_REQ_COMPLETED */
        return;
    case RAMROD_OPCODE_TOE_TERMINATE:        
        DbgBreakIf(! tcp->sp_request);
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_TERMINATE1_OFFLOAD);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        tcp->rx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_TRM_REQ_COMPLETED */
        return;
    case RAMROD_OPCODE_TOE_EMPTY_RAMROD:
        DbgBreakIf(nbytes);
        DbgBreakIf(! tcp->sp_request );
        DbgBreakIf((tcp->sp_request->type != SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT) &&
                   (tcp->sp_request->type != SP_REQUEST_PENDING_REMOTE_DISCONNECT) &&
                   (tcp->sp_request->type != SP_REQUEST_PENDING_TX_RST));
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        return;
    case RAMROD_OPCODE_TOE_INITIATE_OFFLOAD:
        DbgBreakIf(nbytes);
        DbgBreakIf(! tcp->sp_request );
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_INITIATE_OFFLOAD);

        /* 13/08/08 NirV: bugbug, temp workaround for dpc watch dog bug,
         * complete ofld request here - assumption: tcp lock is NOT taken by caller */
        lm_tcp_comp_initiate_offload_request(pdev, tcp, LM_STATUS_SUCCESS);        
        lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_INITIATE_OFFLOAD, tcp->ulp_type, tcp->cid);
        
        return;
    case CMP_OPCODE_TOE_LCN_ERR:
        DbgBreakIf(! tcp->sp_request );
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_INITIATE_OFFLOAD);
        tcp->rx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        return;
    default:
        DbgMessage(pdev, FATAL, "unexpected rx cqe opcode=%d\n", cmd);
        DbgBreakIfAll(TRUE);
    } 
}

u8_t lm_tcp_rx_process_cqes(lm_device_t *pdev, u8_t drv_toe_rss_id, s_list_t * connections)
{
    lm_tcp_rcq_t *rcq;
    lm_tcp_grq_t *grq;
    struct toe_rx_cqe *cqe, *hist_cqe;
    lm_tcp_state_t *tcp = NULL;
    u32_t cid;    
    u32_t avg_dpc_cnt;
    u16_t cq_new_idx;
    u16_t cq_old_idx;
    u16_t num_to_reproduce = 0;
    u8_t  defer_cqe;
    u8_t  process_rss_upd_later = FALSE;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4int , "###lm_tcp_rx_process_cqes START\n");

    rcq = &pdev->toe_info.rcqs[drv_toe_rss_id];
    grq = &pdev->toe_info.grqs[drv_toe_rss_id];
    cq_new_idx = *(rcq->hw_con_idx_ptr);
    cq_old_idx = lm_bd_chain_cons_idx(&rcq->bd_chain);
    DbgBreakIf(S16_SUB(cq_new_idx, cq_old_idx) < 0);     

    /* save statistics */
    rcq->num_cqes_last_dpc = S16_SUB(cq_new_idx, cq_old_idx);
    DbgMessage(pdev, VERBOSEl4int, "###lm_tcp_rx_process_cqes num_cqes=%d\n", rcq->num_cqes_last_dpc);

    if (rcq->num_cqes_last_dpc) {  /* Exclude zeroed value from statistics*/
        if(rcq->max_cqes_per_dpc < rcq->num_cqes_last_dpc) {
            rcq->max_cqes_per_dpc = rcq->num_cqes_last_dpc;
        }
        /* we don't want to wrap around...*/
        if ((rcq->sum_cqes_last_x_dpcs + rcq->num_cqes_last_dpc) < rcq->sum_cqes_last_x_dpcs) {
            rcq->avg_dpc_cnt = 0;
            rcq->sum_cqes_last_x_dpcs = 0;
        }
        rcq->sum_cqes_last_x_dpcs += rcq->num_cqes_last_dpc;
        rcq->avg_dpc_cnt++;
        avg_dpc_cnt = rcq->avg_dpc_cnt;
        if (avg_dpc_cnt) { /*Prevent division by 0*/
            rcq->avg_cqes_per_dpc = rcq->sum_cqes_last_x_dpcs / avg_dpc_cnt;
        } else {
            rcq->sum_cqes_last_x_dpcs = 0;
        }
    }


    /* if we are suspended, we need to check if we can resume processing */
    if (rcq->suspend_processing == TRUE) {
        lm_tcp_rss_update_suspend_rcq(pdev, rcq);
        if (rcq->suspend_processing == TRUE) {
            /* skip the consumption loop */
            cq_new_idx = cq_old_idx;
            DbgMessage(pdev, VERBOSEl4int, "lm_tcp_rx_process_cqes(): rcq suspended - idx:%d\n", drv_toe_rss_id);
        }
    }

    while(cq_old_idx != cq_new_idx) {
        u32_t update_stats_type;
        u8_t opcode;

        DbgBreakIf(S16_SUB(cq_new_idx, cq_old_idx) <= 0);

        /* get next consumed cqe */
        cqe = lm_toe_bd_chain_consume_bd(&rcq->bd_chain);
        update_stats_type = cqe->data.raw_data;
        DbgBreakIf(!cqe); 
        num_to_reproduce++;

        /* get cid and opcode from cqe */
        cid = SW_CID(((cqe->params1 & TOE_RX_CQE_CID) >> TOE_RX_CQE_CID_SHIFT));
        opcode = (cqe->params1 & TOE_RX_CQE_COMPLETION_OPCODE) >> TOE_RX_CQE_COMPLETION_OPCODE_SHIFT; 

        if (opcode == RAMROD_OPCODE_TOE_RSS_UPDATE) {

            /* update the saved consumer */
            cq_old_idx = lm_bd_chain_cons_idx(&rcq->bd_chain);

            /* rss update ramrod */
            DbgMessage(pdev, INFORMl4int, "lm_tcp_rx_process_cqes(): calling lm_tcp_rss_update_ramrod_comp - drv_toe_rss_id:%d\n", drv_toe_rss_id);
            if (num_to_reproduce > 1) {
                process_rss_upd_later = TRUE;
                lm_tcp_rss_update_ramrod_comp(pdev, rcq, cid, update_stats_type, FALSE);
                break;
            }
            lm_tcp_rss_update_ramrod_comp(pdev, rcq, cid, update_stats_type, TRUE);

            /* suspend further RCQ processing (if needed) */
            if (rcq->suspend_processing == TRUE)
                break;
            else
                continue;

        }

        if (cid < MAX_ETH_REG_CONS) {
            /* toe init ramrod */
            DbgBreakIf(((cqe->params1 & TOE_RX_CQE_COMPLETION_OPCODE) >> TOE_RX_CQE_COMPLETION_OPCODE_SHIFT) 
                       != RAMROD_OPCODE_TOE_INIT);
            lm_tcp_init_ramrod_comp(pdev);
            cq_old_idx = lm_bd_chain_cons_idx(&rcq->bd_chain);
            DbgBreakIf(cq_old_idx != cq_new_idx);
            /* We need to update the slow-path ring. This is usually done in the lm_tcp_rx_complete_sp_cqes,
             * but we won't get there since this completion is not associated with a connection. USUALLY we
             * have to update the sp-ring only AFTER we've written the CQ producer, this is to promise that there
             * will always be an empty entry for another ramrod completion, but in this case we're safe, since only
             * one CQE is occupied anyway */
            lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_OPCODE_TOE_INIT, TOE_CONNECTION_TYPE, LM_SW_LEADING_RSS_CID(pdev));
            break;
        }

        tcp = lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, cid);
        DbgBreakIf(!tcp);
        /* save cqe in history_cqes */
        hist_cqe = (struct toe_rx_cqe *)lm_tcp_qe_buffer_next_cqe_override(&tcp->rx_con->history_cqes);
        *hist_cqe = *cqe;

        /* ASSUMPTION: if COMP_DEFERRED changes from FALSE to TRUE, the change occurs only in DPC
         * o/w it can only change from TRUE to FALSE.
         * 
         * Read flag w/o lock. Flag may change by the time we call rx_defer_cqe
         * Need to check again under lock. We want to avoid acquiring the lock every DPC */
        defer_cqe = ((tcp->rx_con->flags & TCP_RX_COMP_DEFERRED) == TCP_RX_COMP_DEFERRED);
        if (defer_cqe) {
            /* if we're deferring completions - just store the cqe and continue to the next one
             * Assumptions: ALL commands need to be deferred, we aren't expecting any command on 
             * L4 that we should pay attention to for this connection ( only one outstanding sp at a time ) */
            /* Return if we are still deferred (may have changed since initial check was w/o a lock */
            mm_acquire_tcp_lock(pdev, tcp->rx_con);
            /* check again under lock if we're deferred */
            defer_cqe = ((tcp->rx_con->flags & TCP_RX_COMP_DEFERRED) == TCP_RX_COMP_DEFERRED);
            if (defer_cqe) {
                tcp->rx_con->flags |= TCP_DEFERRED_PROCESSING;

                /* 13/08/08 NirV: bugbug, temp workaround for dpc watch dog bug,
                 * release the tcp lock if cqe is offload complete */
                if (((cqe->params1 & TOE_RX_CQE_COMPLETION_OPCODE) >> TOE_RX_CQE_COMPLETION_OPCODE_SHIFT) == RAMROD_OPCODE_TOE_INITIATE_OFFLOAD)
                {
                    mm_release_tcp_lock(pdev, tcp->rx_con);
                }

                lm_tcp_rx_process_cqe(pdev,cqe,tcp,drv_toe_rss_id);
            }
            
            /* 13/08/08 NirV: bugbug, temp workaround for dpc watch dog bug,
             * release the tcp lock if cqe is not offload complete (was released earlier) */
            if (((cqe->params1 & TOE_RX_CQE_COMPLETION_OPCODE) >> TOE_RX_CQE_COMPLETION_OPCODE_SHIFT) != RAMROD_OPCODE_TOE_INITIATE_OFFLOAD)
            {            
                mm_release_tcp_lock(pdev, tcp->rx_con);
            }
        }
    
        if (!defer_cqe) {
            /* connections will always be initialized to a dummy, so once a tcp connection is added to the 
             * list, it's link will be initialized to point to another link other than NULL */
            if (s_list_next_entry(&tcp->rx_con->dpc_info.link) == NULL) {
                s_list_push_head(connections, &tcp->rx_con->dpc_info.link);
            }
            lm_tcp_rx_process_cqe(pdev, cqe, tcp, drv_toe_rss_id);
        } 

        cq_old_idx = lm_bd_chain_cons_idx(&rcq->bd_chain);
    }

    /* We may have nothing to reproduce if we were called from a sw_dpc */
    if (num_to_reproduce) {
        lm_toe_bd_chain_bds_produced(&rcq->bd_chain, num_to_reproduce);

        /* GilR 5/13/2006 - TBA - save some stats? */

        /* notify the fw of the prod of the RCQ */
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_CQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id) , PORT_ID(pdev)),
                          lm_bd_chain_prod_idx(&rcq->bd_chain),  BAR_USTRORM_INTMEM);

        if (pdev->params.enable_dynamic_hc[HC_INDEX_TOE_RX_CQ_CONS]) {
            u32_t l4_quasi_byte_counter;
            u16_t prod_idx_diff = lm_bd_chain_prod_idx(&rcq->bd_chain) - rcq->bd_chain.bds_per_page * rcq->bd_chain.page_cnt;
            l4_quasi_byte_counter = prod_idx_diff;
            l4_quasi_byte_counter <<= 16;
            //fIXME
            LM_INTMEM_WRITE32(pdev, rcq->hc_sb_info.iro_dhc_offset, l4_quasi_byte_counter, BAR_CSTRORM_INTMEM);
        }
    }
    DbgMessage(pdev, VERBOSEl4int , "###lm_tcp_rx_process_cqes END\n");
    return process_rss_upd_later;
}

/** Description
 *  compensate the grq
 *  Assumption:
 *    called under the GRQ LOCK
 */ 
void lm_tcp_rx_compensate_grq(lm_device_t * pdev, u8_t drv_toe_rss_id)
{
    d_list_t * collected_gen_bufs_list = &pdev->toe_info.grqs[drv_toe_rss_id].aux_gen_list;

    MM_ACQUIRE_TOE_GRQ_LOCK_DPC(pdev, drv_toe_rss_id);
    if (lm_tcp_rx_fill_grq(pdev, drv_toe_rss_id, collected_gen_bufs_list,FILL_GRQ_FULL)) {
        DbgMessage(pdev, INFORMl4rx, "lm_toe_service_rx_intr: Updating GRQ producer\n");
        /* notify the fw of the prod of the GRQ */
        LM_INTMEM_WRITE16(pdev, USTORM_TOE_GRQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id) , PORT_ID(pdev)), 
                          lm_bd_chain_prod_idx(&pdev->toe_info.grqs[drv_toe_rss_id].bd_chain), BAR_USTRORM_INTMEM); 
    }
    /* check if occupancy is above threshold */
    if (pdev->toe_info.grqs[drv_toe_rss_id].bd_chain.capacity - pdev->toe_info.grqs[drv_toe_rss_id].bd_chain.bd_left < GRQ_XON_TH) {
        pdev->toe_info.grqs[drv_toe_rss_id].grq_compensate_on_alloc = TRUE;
    } else {
        pdev->toe_info.grqs[drv_toe_rss_id].grq_compensate_on_alloc = FALSE; 
    }
    
    MM_RELEASE_TOE_GRQ_LOCK_DPC(pdev, drv_toe_rss_id);

    if (!d_list_is_empty(collected_gen_bufs_list)) {
        mm_tcp_return_list_of_gen_bufs(pdev,collected_gen_bufs_list,0, NON_EXISTENT_SB_IDX);
        d_list_clear(collected_gen_bufs_list);
    }
}

static __inline void lm_tcp_rx_lock_grq(lm_device_t *pdev, u8_t drv_toe_rss_id)
{
    /* If we've asked for compensation on allocation (which is only set from within a dpc) 
     * there is a risk of the grq being accessed from a different context (the alloc context) 
     * therefore, we cancel this option. Needs to be under lock in case alloc context is already
     * compensating */
    if (pdev->toe_info.grqs[drv_toe_rss_id].grq_compensate_on_alloc) {
        MM_ACQUIRE_TOE_GRQ_LOCK_DPC(pdev, drv_toe_rss_id);
        pdev->toe_info.grqs[drv_toe_rss_id].grq_compensate_on_alloc = FALSE;
        MM_RELEASE_TOE_GRQ_LOCK_DPC(pdev, drv_toe_rss_id);
    }
}

void lm_toe_service_rx_intr(lm_device_t *pdev, u8_t drv_toe_rss_id)
{
    s_list_t         connections;
    s_list_entry_t   dummy;
    lm_tcp_con_t   * con;
    lm_tcp_state_t * tcp;
    u32_t            dbg_loop_cnt = 0;
    u8_t             process_rss_upd;

    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4int , "###lm_toe_service_rx_intr START\n");
    DbgBreakIf(!(pdev && ARRSIZE(pdev->toe_info.rcqs) > drv_toe_rss_id));

    /* lock the grq from external access: i.e.. allocation compensation */
    lm_tcp_rx_lock_grq(pdev, drv_toe_rss_id);

    while (TRUE) {
        dbg_loop_cnt++;
        s_list_clear(&connections);
        s_list_push_head(&connections, &dummy);
        /* process the cqes and initialize connections with all the connections that appeared
         * in the DPC */
        process_rss_upd = lm_tcp_rx_process_cqes(pdev,drv_toe_rss_id,&connections);
    
        /* Compensate the GRQ with generic buffers from the pool : process_cqes takes buffers from the grq */
        lm_tcp_rx_compensate_grq(pdev,drv_toe_rss_id);
    
        /* FP: traverse the connections. remember to ignore the last one */
        con = (lm_tcp_con_t *)s_list_peek_head(&connections);
        tcp = con->tcp_state;
        while (s_list_next_entry(&con->dpc_info.link) != NULL) {
            mm_acquire_tcp_lock(pdev, con);
            lm_tcp_rx_complete_tcp_fp(pdev, con->tcp_state, con);
            mm_release_tcp_lock(pdev, con);
            con = (lm_tcp_con_t *)s_list_next_entry(&con->dpc_info.link);
            tcp = con->tcp_state;
        }
    
        /* SP : traverse the connections. remember to ignore the last one */
        con = (lm_tcp_con_t *)s_list_pop_head(&connections);
        s_list_next_entry(&con->dpc_info.link) = NULL;
        tcp = con->tcp_state;
        while (s_list_entry_cnt(&connections) > 0) {
            /* we access snapshot and not dpc, since once the dpc_flags were copied
             * to snapshot they were zeroized */
            if (con->dpc_info.snapshot_flags) {
                lm_tcp_rx_complete_tcp_sp(pdev, tcp, con);
            }
            con = (lm_tcp_con_t *)s_list_pop_head(&connections);
            s_list_next_entry(&con->dpc_info.link) = NULL;
            tcp = con->tcp_state;
        }
        
        if (process_rss_upd) {
            lm_tcp_rss_update_suspend_rcq(pdev,&pdev->toe_info.rcqs[drv_toe_rss_id]);
            if (!pdev->toe_info.rcqs[drv_toe_rss_id].suspend_processing) {
                pdev->toe_info.rcqs[drv_toe_rss_id].rss_update_processing_continued++;
                continue;
            }
        }
        break;
    }
    if (pdev->toe_info.rcqs[drv_toe_rss_id].rss_update_processing_max_continued < dbg_loop_cnt) {
        pdev->toe_info.rcqs[drv_toe_rss_id].rss_update_processing_max_continued = dbg_loop_cnt;
    }

    if (pdev->toe_info.grqs[drv_toe_rss_id].number_of_isles_delta || pdev->toe_info.grqs[drv_toe_rss_id].gen_bufs_in_isles_delta) {
        MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC(pdev);
        lm_tcp_update_isles_cnts(pdev, pdev->toe_info.grqs[drv_toe_rss_id].number_of_isles_delta, 
                                 pdev->toe_info.grqs[drv_toe_rss_id].gen_bufs_in_isles_delta);
        MM_RELEASE_ISLES_CONTROL_LOCK_DPC(pdev);
        pdev->toe_info.grqs[drv_toe_rss_id].number_of_isles_delta = pdev->toe_info.grqs[drv_toe_rss_id].gen_bufs_in_isles_delta = 0;
    }

    DbgMessage(pdev, VERBOSEl4int , "###lm_toe_service_rx_intr END\n");
}

/** Description:
 *  Post a single tcp buffer to the Rx bd chain
 * Assumptions:
 *  - caller initiated tcp_buf->flags field with BUFFER_START/BUFFER_END/PUSH appropriately
 * Returns:
 *  - SUCCESS - tcp buf was successfully attached to the bd chain
 *  - RESOURCE - not enough available BDs on bd chain for given tcp buf
 *  - CONNECTION_CLOSED - whenever connection's flag are marked as 'POST BLOCKED' */
lm_status_t lm_tcp_rx_post_buf(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_buffer_t     *tcp_buf,
    lm_frag_list_t      *frag_list
    )
{
    lm_tcp_con_t             * rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_status_t                lm_stat      = LM_STATUS_SUCCESS;
    d_list_t                   return_list; /* buffers to return to pool in case of copying to buffer */
    u32_t                      copied_bytes = 0;
    u32_t                      add_sws_bytes = 0;
    u8_t                       split_buffer = FALSE; 

    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_post_buf cid=%d\n", tcp->cid);
    DbgBreakIf(!(pdev && tcp)); 
    DbgBreakIf(tcp->cid && (tcp != lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, tcp->cid)));
    /* (tcp_buf==NULL <=> frag_list==NULL) && (frag_list!= NULL => frag_list->cnt != 0) */
    DbgBreakIf( ( ! ( ( (!tcp_buf) && (!frag_list) ) || (tcp_buf && frag_list) ) ) ||
                ( frag_list && (frag_list->cnt == 0) ) ); 

    rx_con = tcp->rx_con;
    if ( GET_FLAGS(rx_con->flags, TCP_RX_POST_BLOCKED) ) {
//        DbgBreakIf(!tcp_buf); /* (lm_tcp_rx_post_buf design guides VBD doc) */
        if (!tcp_buf) {
            tcp->rx_con->zb_rx_post_blocked++;
            return LM_STATUS_SUCCESS;
        } else {
            tcp->rx_con->rx_post_blocked++;
            return LM_STATUS_CONNECTION_CLOSED;
        }
    }

    /* TCP_POST_DELAYED is turned on when the lm can not process new buffers for some reason, but not permanently 
     * Assumption: UM will eventually try to repost this buffer... */
    if ( GET_FLAGS(rx_con->flags, TCP_POST_DELAYED)) {
        return LM_STATUS_FAILURE;
    }

    RESET_FLAGS(rx_con->flags, TCP_INDICATE_REJECTED);

    /* set tcp_buf fields */
    if (tcp_buf) {
        /* check bd chain availability  */
        if(lm_bd_chain_avail_bds(&rx_con->bd_chain) < frag_list->cnt) {
            DbgBreakIf(s_list_is_empty(&rx_con->active_tb_list));
            /* Check if the last placed BD was part of a split buffer (no end flag) if so, mark is at special split-end
             * and give a doorbell as if it was with END. Also, block UM from giving us more buffers until we've completed
             * this one (See L4 VBD Spec for more details on "Large Application Buffers" */
            if (!(GET_FLAGS(rx_con->u.rx.last_rx_bd->flags , TOE_RX_BD_END))) {
                SET_FLAGS(rx_con->u.rx.last_rx_bd->flags, (TOE_RX_BD_END | TOE_RX_BD_SPLIT));
                /* Mark the last buffer in active-tb-list as 'special' so that we know when we complete it that we can
                 * unblock UM... */
                tcp_buf = (lm_tcp_buffer_t *)s_list_peek_tail(&rx_con->active_tb_list);
                SET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_SPLIT);
                SET_FLAGS(rx_con->flags, TCP_POST_DELAYED);
                lm_tcp_rx_write_db(pdev, tcp);
            }
            DbgMessage(pdev, INFORMl4rx, "post rx buf failed, rx chain is full (cid=%d, avail bds=%d, buf nfrags=%d)\n",
                        tcp->cid, lm_bd_chain_avail_bds(&rx_con->bd_chain), frag_list->cnt);
            return LM_STATUS_RESOURCE; 
        }

        tcp_buf->size = tcp_buf->more_to_comp = (u32_t)frag_list->size;
        tcp_buf->bd_used = 0; /* will be modified if buffer will be posted */
        DbgBreakIf(!(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_START ?
                 rx_con->app_buf_bytes_acc_post == 0 :
                 rx_con->app_buf_bytes_acc_post > 0));
        rx_con->app_buf_bytes_acc_post += tcp_buf->size;    

        /* special care in case of last tcp buffer of an application buffer */
        if(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END) {
            tcp_buf->app_buf_xferred = 0; /* just for safety */
            tcp_buf->app_buf_size = rx_con->app_buf_bytes_acc_post;
            rx_con->app_buf_bytes_acc_post = 0;
        }
        split_buffer = !(GET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_POST_START) && GET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_POST_END));
    } else {
        /* zero-byte request */
        rx_con->u.rx.rx_zero_byte_recv_reqs++;
    }

    /* we could be in the middle of completing a split-buffer... this is in case the previous split buffer was posted partially and we got a 
     * cmp with push... need to complete it here. */
    if (GET_FLAGS(rx_con->flags, TCP_POST_COMPLETE_SPLIT)) {
        DbgBreakIf(!split_buffer); /* we can only be in this state if we're completing split buffers... */
        rx_con->bytes_push_skip_cnt += tcp_buf->more_to_comp; /* how many bytes did we skip? */
        tcp_buf->more_to_comp = 0;
        rx_con->partially_completed_buf_cnt++;
        /* complete buffer */
        s_list_push_tail(&(tcp->rx_con->active_tb_list), &(tcp_buf->link));
        rx_con->rq_nbytes += tcp_buf->size;
        rx_con->buffer_skip_post_cnt++;
        lm_tcp_complete_tcp_buf(pdev, tcp, rx_con,tcp_buf,0);
        return LM_STATUS_SUCCESS;
    }

    gen_info = &rx_con->u.rx.gen_info;

    if ( gen_info->peninsula_nbytes ) {
        DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_post_buf WITH GENERIC, cid=%d, tcp_buf=%p, buf_size=%d, buf_flags=%d, peninsula_nbytes=%d\n",
                tcp->cid, tcp_buf, frag_list ? frag_list->size : 0, tcp_buf ? tcp_buf->flags : 0, rx_con->u.rx.gen_info.peninsula_nbytes);
        if (tcp_buf) {
            d_list_init(&return_list, NULL, NULL, 0);
            copied_bytes = lm_tcp_rx_peninsula_to_rq_copy(pdev,tcp,tcp_buf,&return_list, 0xffffffff, FALSE);
            gen_info->bytes_copied_cnt_in_post += copied_bytes;
            if (!d_list_is_empty(&return_list)) {
                lm_tcp_return_list_of_gen_bufs(pdev,tcp,&return_list, MM_TCP_RGB_COMPENSATE_GRQS, NON_EXISTENT_SB_IDX);
            }
            if ((copied_bytes == tcp_buf->size) && !split_buffer && s_list_is_empty(&rx_con->active_tb_list)) {
                /* consumed_cnt: our way of telling fw we bypassed it */
                lm_tcp_incr_consumed_gen(pdev, tcp, tcp_buf->size);
                /* simulate a _lm_tcp_rx_post_buf for lm_tcp_complete_bufs */
                s_list_push_tail(&(tcp->rx_con->active_tb_list), &(tcp_buf->link));
                rx_con->rq_nbytes += tcp_buf->size;
                rx_con->buffer_skip_post_cnt++;
                rx_con->bytes_skip_post_cnt += copied_bytes;
                /* If we copied some bytes to the RQ, we can now compensate FW-Window with these copied bytes. */
                add_sws_bytes += copied_bytes;
                /* this function completes nbytes on the tcp buf and may complete the buffer if more_to_comp = 0*/
                lm_tcp_complete_tcp_buf(pdev, tcp, rx_con,tcp_buf,copied_bytes);
            } else {
                /* will be posted and therefore get a SKP at some stage. */
                if (!GET_FLAGS(rx_con->flags, TCP_POST_NO_SKP)) {
                    rx_con->u.rx.skp_bytes_copied += copied_bytes;
                }
                lm_stat = _lm_tcp_rx_post_buf(pdev, tcp, tcp_buf, frag_list);
                DbgBreakIf(lm_stat != LM_STATUS_SUCCESS);
                if (copied_bytes && GET_FLAGS(rx_con->flags, TCP_POST_NO_SKP)) {
                    lm_tcp_rx_write_db(pdev, tcp); /* for the case of split buffer in which bytes/bds are accumulated in bd_more* fields. bd_more* fields must be cleaned at this phase  */
                    rx_con->bytes_comp_cnt += copied_bytes;
                    /* If we copied some bytes to the RQ, we can now compensate FW-Window with these copied bytes. */
                    add_sws_bytes += copied_bytes;
                    /* this function completes nbytes on the tcp buf and may complete the buffer if more_to_comp = 0*/
                    lm_tcp_complete_tcp_buf(pdev, tcp, rx_con,tcp_buf,copied_bytes);
                }
            }
        }   
        /* if we have something to indicate after copying and it's ok to indicate... - indicate it */
        if (gen_info->peninsula_nbytes && _lm_tcp_ok_to_indicate(rx_con)) {
            DbgBreakIf(frag_list && (frag_list->size != copied_bytes)); /* can't have bytes left with free space in tcp buf */
            mm_tcp_rx_indicate_gen(pdev, tcp);
            add_sws_bytes += gen_info->add_sws_bytes; /* any bytes we need to update will be aggregated here during indicate */
            gen_info->add_sws_bytes = 0;

        } 
    } else if (tcp_buf) {        
        DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_post_buf NO COPY, cid=%d, tcp_buf=%p, buf_size=%d, buf_flags=%d, peninsula_nbytes=%d\n",
            tcp->cid, tcp_buf, frag_list->size, tcp_buf->flags, rx_con->u.rx.gen_info.peninsula_nbytes);
        lm_stat = _lm_tcp_rx_post_buf(pdev, tcp, tcp_buf, frag_list);
        DbgBreakIf(lm_stat != LM_STATUS_SUCCESS);
    }

    if (add_sws_bytes) {
        lm_tcp_rx_post_sws(pdev, tcp, rx_con, add_sws_bytes, TCP_RX_POST_SWS_INC);
    }

    
    return lm_stat;
}


/* Assumptions:
 *  - caller initiated appropriately the following fields: 
 *      - tcp_buf->flags 
 *      - tcp_buf->size, tcp_buf->more_to_comp
 *      - tcp_buf->app_buf_size, tcp_buf->app_buf_xferred 
 *  - caller verified that there is enough availabe BDs in the BD chain for the given buffer */
static lm_status_t _lm_tcp_rx_post_buf(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_buffer_t     *tcp_buf,
    lm_frag_list_t      *frag_list
    )
{
    lm_tcp_con_t *rx_con = tcp->rx_con;
    lm_bd_chain_t * rx_chain;
    u16_t old_prod, new_prod;
    struct toe_rx_bd * rx_bd;
    lm_frag_t * frag = frag_list->frag_arr;
    u32_t  dbg_buf_size = 0;
    u32_t  bd_bytes_prod; /* Each bd is initialized with a cyclic counter of bytes prod until that bd. */
    u16_t  flags = 0;
    u32_t i;

    /* Number of fragments of entire application buffer can't be bigger 
     * than size of the BD chain (entire application buffer since we can't 
     * post partial application buffer to the FW , db_more_bds however includes the "next" bd, so we need
     * to take that into consideration as well */
    DbgBreakIfAll( (rx_con->db_more_bds + frag_list->cnt) > (u32_t)(rx_con->bd_chain.capacity + rx_con->bd_chain.page_cnt));

    rx_chain = &rx_con->bd_chain;
    DbgBreakIf(lm_bd_chain_avail_bds(rx_chain) < frag_list->cnt);

    old_prod = lm_bd_chain_prod_idx(rx_chain);

    /* First BD should have the START flag */
    if(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_START) {
        flags = TOE_RX_BD_START;
    }    

    /* Set NO_PUSH flag if needed */
    if ( tcp_buf->flags & TCP_BUF_FLAG_L4_RX_NO_PUSH ) {
        flags |= TOE_RX_BD_NO_PUSH;
    }
    if (tcp_buf->flags & TCP_BUF_FLAG_L4_PARTIAL_FILLED) {
        if (!rx_con->partially_filled_buf_sent && !rx_con->rq_completion_calls) {
            SET_FLAGS(rx_con->db_data.rx->flags, TOE_RX_DB_DATA_PARTIAL_FILLED_BUF);
        } else {
            RESET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_PARTIAL_FILLED);
        }
        rx_con->partially_filled_buf_sent++;
    }
    /* Attach the first frag to the BD-chain */
    bd_bytes_prod = rx_con->db_data.rx->bytes_prod + rx_con->db_more_bytes;
    rx_bd = _lm_tcp_rx_set_bd(frag, flags, rx_chain, bd_bytes_prod);
    bd_bytes_prod += frag->size;
    dbg_buf_size += frag->size;
    flags &= ~TOE_RX_BD_START;
    frag++;

     /* "attach" the frags to the bd chain */
    for(i = 1; i < frag_list->cnt; i++, frag++) {
        rx_bd = _lm_tcp_rx_set_bd(frag, flags, rx_chain, bd_bytes_prod);
        dbg_buf_size += frag->size;
        bd_bytes_prod += frag->size;
    }
    tcp->rx_con->u.rx.last_rx_bd = rx_bd;

    /* The last BD must have the END flag */
    if(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END) {
        rx_bd->flags |= TOE_RX_BD_END;
        DbgMessage(NULL, VERBOSEl4rx, "Setting Rx last BD flags=0x%x\n", rx_bd->flags);
    }

    DbgBreakIf(frag_list->cnt > TCP_MAX_SGL_SIZE);
    tcp_buf->bd_used = frag_list->cnt & TCP_MAX_SGL_SIZE;    
    DbgBreakIf(tcp_buf->size != dbg_buf_size);

    /* Perpare data for a DoorBell */
    rx_con->db_more_bytes += tcp_buf->size;
    new_prod = lm_bd_chain_prod_idx(rx_chain);
    DbgBreakIf(S16_SUB(new_prod, old_prod) < tcp_buf->bd_used);
    rx_con->db_more_bds += S16_SUB(new_prod, old_prod);
    rx_con->db_more_bufs++;

    /* Enqueue the buffer to the active_tb_list */
    s_list_push_tail(&(rx_con->active_tb_list), &(tcp_buf->link));
    rx_con->rq_nbytes += tcp_buf->size;

    if(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END) {
        lm_tcp_rx_write_db(pdev, tcp);
    }


    return LM_STATUS_SUCCESS;
}

static lm_status_t _lm_tcp_rx_get_buffered_data(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    lm_frag_list_t     ** frag_list,  /* if *frag_list is NULL, the rx con pre-allocaed will be used */
    lm_tcp_gen_buf_t   ** gen_buf
    )
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_tcp_gen_buf_t         * head_of_indication;
    d_list_t                   indicate_list;
    d_list_entry_t           * entry;
    lm_tcp_gen_buf_t         * curr_gen_buf;
    u32_t                      gen_offset, i;
    u32_t                      num_bufs_to_indicate;
    u32_t                      ind_nbufs=0, ind_nbytes=0;
    u8_t                       dont_send_to_system_more_then_rwin;
    DbgMessage(pdev, VERBOSEl4rx, "###_lm_tcp_rx_get_buffered_data cid=%d\n", tcp->cid);

    gen_info = &rx_con->u.rx.gen_info;


    if ((u16_t)tcp->tcp_cached.rcv_indication_size != 0) {
        DbgBreakMsg("MichalS rcv_indication_size != 0 not implemented\n");
       /* MichalS TBA: RcvIndicationSize > 0 will change following block quite a lot */
    }

    num_bufs_to_indicate = d_list_entry_cnt(&gen_info->peninsula_list);

    /* The buffers in peninsula_list are ALWAYS released, unreleased buffers are in the dpc_peninsula_list. */
    DbgBreakIf(((lm_tcp_gen_buf_t *)d_list_peek_tail(&gen_info->peninsula_list))->placed_bytes == 0);

    if (*frag_list == NULL) {
        *frag_list = gen_info->frag_list;
        (*frag_list)->cnt = gen_info->max_frag_count;
    }

    if (num_bufs_to_indicate > (*frag_list)->cnt) {
        DbgMessage(pdev, WARNl4rx, "_lm_tcp_rx_get_buffered_data: number of buffers to indicate[%d] is larger than frag_cnt[%d] cid=%d\n",
                num_bufs_to_indicate, (*frag_list)->cnt, tcp->cid);
        num_bufs_to_indicate = gen_info->max_frag_count;
        gen_info->num_non_full_indications++;           
    }
    d_list_init(&indicate_list, NULL, NULL, 0);
    dont_send_to_system_more_then_rwin = (u8_t)gen_info->dont_send_to_system_more_then_rwin;
    while (num_bufs_to_indicate--) {
        entry = d_list_pop_head(&gen_info->peninsula_list);
        DbgBreakIf(entry == NULL);
        if (dont_send_to_system_more_then_rwin) {
            if ((ind_nbytes + ((lm_tcp_gen_buf_t *)entry)->placed_bytes) 
                    > tcp->tcp_cached.initial_rcv_wnd) {
                if (ind_nbytes) {
                    d_list_push_head(&gen_info->peninsula_list, entry);
                    break;
                } else {
                    dont_send_to_system_more_then_rwin = FALSE;
                }
            }
        }
        d_list_push_tail(&indicate_list, entry);
        ind_nbufs ++;
        ind_nbytes += ((lm_tcp_gen_buf_t *)entry)->placed_bytes;
    }

    ind_nbytes -= gen_info->first_buf_offset;

    head_of_indication = (lm_tcp_gen_buf_t *)d_list_peek_head(&indicate_list);

    if CHK_NULL(head_of_indication)
    {
        DbgBreakIfAll( !head_of_indication ) ;
        return LM_STATUS_FAILURE ;         
    }

    head_of_indication->tcp = tcp;
    head_of_indication->ind_nbufs = ind_nbufs;
    head_of_indication->ind_bytes = ind_nbytes;
    DbgBreakIf(gen_info->peninsula_nbytes < ind_nbytes);
    gen_info->peninsula_nbytes -= ind_nbytes;

    /* initialize frag list */
    (*frag_list)->cnt  = ind_nbufs;
    (*frag_list)->size = ind_nbytes;
    curr_gen_buf = head_of_indication;

    gen_offset = gen_info->first_buf_offset;
    for (i = 0; i < (*frag_list)->cnt; i++ ) {
        (*frag_list)->frag_arr[i].addr.as_ptr = curr_gen_buf->buf_virt + gen_offset;
        (*frag_list)->frag_arr[i].size = curr_gen_buf->placed_bytes - gen_offset;
        curr_gen_buf = NEXT_GEN_BUF(curr_gen_buf);
        gen_offset = 0;  /* only first buffer can have an offset */
        /* we don't touch gen_info->first_buf_offset - this is handled in lm_tcp_rx_buffered_data_indicated */
    }    
    *gen_buf = head_of_indication;
    DbgMessage(pdev, VERBOSEl4rx, "###_lm_tcp_rx_get_buffered_data ind_bytes = %d\n", (*frag_list)->size);

    mm_atomic_inc(&pdev->toe_info.stats.total_indicated);
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_tcp_rx_get_buffered_data_from_terminate (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    lm_frag_list_t     ** frag_list, 
    lm_tcp_gen_buf_t   ** gen_buf
    )
{
    lm_tcp_con_t             * rx_con           = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    u16_t                      buff_cnt;
    lm_tcp_gen_buf_t         * unwanted_gen_buf = NULL;
    lm_tcp_gen_buf_t         * temp_gen_buf     = NULL;
    lm_status_t                lm_status        = LM_STATUS_SUCCESS;
            
    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_get_buffered_data_from_terminate cid=%d\n", tcp->cid);

    gen_info = &rx_con->u.rx.gen_info;

    /* make sure ALL the peninsula is released */
    DbgBreakIf(!d_list_is_empty(&gen_info->peninsula_list) &&
               (((lm_tcp_gen_buf_t *)d_list_peek_tail(&gen_info->peninsula_list))->placed_bytes == 0));

    *frag_list = NULL;
    if (gen_info->peninsula_nbytes == 0) {        
        return LM_STATUS_SUCCESS;
    }

/*  DbgBreakIf(gen_info->peninsula_nbytes > tcp->tcp_cached.initial_rcv_wnd);*/
    gen_info->dont_send_to_system_more_then_rwin = FALSE;
    if ((buff_cnt = (u16_t)d_list_entry_cnt(&gen_info->peninsula_list)) > gen_info->max_frag_count) {
        lm_bd_chain_t *bd_chain = &tcp->rx_con->bd_chain;
        u16_t possible_frag_count, decreased_count;
        possible_frag_count = (/*bd_chain->page_cnt**/
                               LM_PAGE_SIZE - sizeof(lm_frag_list_t)) / sizeof(lm_frag_t);
        DbgMessage(pdev, WARNl4rx | WARNl4sp,
                    "###lm_tcp_rx_get_buffered_data_from_terminate cid=%d: peninsula_list cnt (%d) > max frag_count (%d)\n",
                    tcp->cid, buff_cnt, gen_info->max_frag_count);

        if (possible_frag_count > gen_info->max_frag_count) {
            /* This solution is ugly:
                since there will not be any further buffered data indications to the client, we must be able to 
                indicate all the buffered data now. But the preallocated frag list in the rx con is too short! 
                So instead of the pre-allocated frag list we need to use a larger memory. Our options:
                1. allocate memory here and release it later. 
                2. use other pre-allocated memory that is not in use anymore (e.g. the bd chain) [chosen solution] 
                In any case both solutions may fail: memory allocation can fail and the other pre-allocated memory
                might also be too short. the fallback from this is:
                - don't indicate anything and release the peninsula (NOT IMPLEMENTED) 
            DbgBreakIfAll((u16_t)(sizeof(lm_frag_list_t) + sizeof(lm_frag_t)*buff_cnt) > bd_chain->page_cnt*LM_PAGE_SIZE); */
            if (possible_frag_count < buff_cnt) {
                decreased_count = possible_frag_count;   
                DbgMessage(pdev, WARNl4rx | WARNl4sp,
                            "###lm_tcp_rx_get_buffered_data_from_terminate cid=%d: peninsula_list cnt (%d) > aux.frag_cnt (%d)\n",
                            tcp->cid, buff_cnt, possible_frag_count);
            } else {
                decreased_count = 0;            
                DbgMessage(pdev, WARNl4rx | WARNl4sp,
                            "###lm_tcp_rx_get_buffered_data_from_terminate cid=%d: aux.frag_cnt (%d) is enough for %d buffs\n",
                            tcp->cid, possible_frag_count, buff_cnt);
            }
            *frag_list = (lm_frag_list_t*)bd_chain->bd_chain_virt;
            (*frag_list)->cnt = possible_frag_count;
            (*frag_list)->size = 0;
        } else {
            decreased_count = (u16_t)gen_info->max_frag_count;
        }
        if (decreased_count) {
            u16_t returned_buff_cnt = lm_squeeze_rx_buffer_list(pdev, tcp, decreased_count, &unwanted_gen_buf);
            if (decreased_count < returned_buff_cnt) {
                lm_frag_list_t* new_frag_list;
                u32_t mem_size_for_new_frag_list = returned_buff_cnt * sizeof(lm_frag_t) + sizeof(lm_frag_list_t);
//                new_frag_list = (lm_frag_list_t*)mm_alloc_mem(pdev, mem_size_for_new_frag_list, LM_RESOURCE_NDIS);
                new_frag_list = (lm_frag_list_t*)mm_rt_alloc_mem(pdev, mem_size_for_new_frag_list, LM_RESOURCE_NDIS);

                if (new_frag_list != NULL) {
                    tcp->type_of_aux_memory = TCP_CON_AUX_RT_MEM;
                    tcp->aux_memory = new_frag_list;
                    tcp->aux_mem_size = mem_size_for_new_frag_list;
                    *frag_list = new_frag_list;
                    (*frag_list)->cnt = returned_buff_cnt;
                    (*frag_list)->size = 0;
                    tcp->aux_mem_flag = TCP_CON_AUX_RT_MEM_SUCCSESS_ALLOCATION;
                } else {
                    /* No way. Let's send up only part of data. Data distortion is unavoidable.
                       TODO: prevent data distortion by termination the connection itself at least */
                    lm_status = LM_STATUS_RESOURCE;
                    tcp->aux_mem_flag = TCP_CON_AUX_RT_MEM_FAILED_ALLOCATION;
                    /* Get rid of whatever remains in the peninsula...add it to unwanted... */
                    if (unwanted_gen_buf)
                    {
                        temp_gen_buf = (lm_tcp_gen_buf_t*)d_list_peek_tail(&gen_info->peninsula_list);
                        if (temp_gen_buf)
                        {
                            temp_gen_buf->link.next = &(unwanted_gen_buf->link);
                            unwanted_gen_buf->link.prev = &(temp_gen_buf->link);
                            unwanted_gen_buf = (lm_tcp_gen_buf_t*)d_list_peek_head(&gen_info->peninsula_list);
                        }
                    }
                    else
                    {   
                        unwanted_gen_buf = (lm_tcp_gen_buf_t*)d_list_peek_head(&gen_info->peninsula_list);
                    }
                    d_list_clear(&gen_info->peninsula_list);
                    
                }
            }
        }
    }
    if (lm_status == LM_STATUS_SUCCESS) 
    {
        _lm_tcp_rx_get_buffered_data(pdev, tcp, frag_list, gen_buf);
        
        /* for cleaness: lm_tcp_rx_buffered_data_indicated will not be called 
         * indication is 'succesfull' */
        gen_info->num_bytes_indicated += (u32_t)(*frag_list)->size;
        gen_info->first_buf_offset = 0; 
        gen_info->num_buffers_indicated += (*gen_buf)->ind_nbufs;
    }
    
    gen_info->peninsula_blocked = TRUE;
    
    if (unwanted_gen_buf) {
         lm_tcp_return_gen_bufs(pdev, tcp, unwanted_gen_buf,MM_TCP_RGB_COMPENSATE_GRQS, NON_EXISTENT_SB_IDX);
    }

    if (*gen_buf) {
        /* with data taken from terminate, we can always act as in 'short-loop' since the bytes for 
         * this connection won't increase the window anyway... */
        (*gen_buf)->flags &= ~GEN_FLAG_SWS_UPDATE;
    }
    
    return lm_status;
}

lm_status_t lm_tcp_rx_get_buffered_data(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    lm_frag_list_t     ** frag_list, 
    lm_tcp_gen_buf_t   ** gen_buf
    )
{
    lm_tcp_con_t             * rx_con = tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info;
    lm_status_t                lm_status;
            
    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_get_buffered_data cid=%d\n", tcp->cid);
    gen_info = &rx_con->u.rx.gen_info;

    DbgBreakIf(gen_info->peninsula_blocked == TRUE); /* terminate was already called */

    if (gen_info->peninsula_nbytes == 0 || (rx_con->flags & TCP_RX_IND_BLOCKED)) {
        return LM_STATUS_FAILURE;
    }

    *frag_list = NULL;
    lm_status = _lm_tcp_rx_get_buffered_data(pdev, tcp, frag_list, gen_buf);
    if (*gen_buf) {
        if (gen_info->update_window_mode == LM_TOE_UPDATE_MODE_LONG_LOOP) {
            gen_info->pending_indicated_bytes += (*gen_buf)->ind_bytes;
            /* We need to increase the number of pending return indications here, since once we return
             * we are basically pending for the return of this specific indication. There are two cases
             * that require decreasing the pending return indications. The first is if the indication failed
             * the second is if it succeeded AND the buffers returned... */
             gen_info->pending_return_indications++;
            (*gen_buf)->flags |= GEN_FLAG_SWS_UPDATE;
        } else {
            (*gen_buf)->flags &= ~GEN_FLAG_SWS_UPDATE;
        }
    }
    
    return LM_STATUS_SUCCESS;
}

void lm_tcp_rx_buffered_data_indicated(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u32_t                 accepted_bytes,
    lm_tcp_gen_buf_t    * gen_buf /* head of indications generic buffer NULL if indication succeeded */
    )
{
    lm_tcp_con_rx_gen_info_t * gen_info = &tcp->rx_con->u.rx.gen_info;

    DbgMessage(pdev, VERBOSEl4rx , "###lm_tcp_rx_buffered_data_indicated accepted_bytes = %d cid=%d\n", accepted_bytes, tcp->cid);

    DbgBreakIf(gen_info->peninsula_blocked == TRUE); /* terminate was already called */

    lm_tcp_incr_consumed_gen(pdev, tcp, accepted_bytes);
    gen_info->num_bytes_indicated += accepted_bytes;

    if (gen_buf == NULL) { /* succesfull indication */
        gen_info->first_buf_offset = 0; 
        if (gen_info->update_window_mode == LM_TOE_UPDATE_MODE_SHORT_LOOP) {
            gen_info->add_sws_bytes += accepted_bytes;
        }
        gen_info->num_success_indicates++;
        gen_info->bytes_indicated_accepted += accepted_bytes;
        tcp->rx_con->u.rx.zero_byte_posted_during_ind = FALSE;
    } else {  /* complete rejection / partial success, gen_buf remains in our control  */
        /* indication failed */
        lm_tcp_gen_buf_t * curr_gen_buf, * ret_buf;
        d_list_t          return_to_pool_list;
        d_list_t          return_to_peninsula_list;
        u32_t             nbytes;
        DbgBreakIf(accepted_bytes > gen_buf->ind_bytes);
        gen_info->peninsula_nbytes += gen_buf->ind_bytes - accepted_bytes;

        gen_info->num_failed_indicates++;
        gen_info->bytes_indicated_accepted+= accepted_bytes;
        gen_info->bytes_indicated_rejected+= gen_buf->ind_bytes - accepted_bytes;
        
        DbgMessage(pdev, INFORMl4rx, "GENERIC: %s Indication for cid=%d accepted_bytes=%d\n",
                    (accepted_bytes == 0)? "Rejected" : "Partial", tcp->cid, accepted_bytes);

        d_list_init(&return_to_pool_list, NULL, NULL, 0);
        d_list_init(&return_to_peninsula_list, NULL, NULL, 0);

        DbgBreakIf(gen_buf->tcp->rx_con->flags & TCP_INDICATE_REJECTED);
        if (tcp->rx_con->u.rx.zero_byte_posted_during_ind) {
            tcp->rx_con->u.rx.zero_byte_posted_during_ind = FALSE;
        } else {
            gen_buf->tcp->rx_con->flags |= TCP_INDICATE_REJECTED;
        }

        curr_gen_buf = gen_buf;

        /* indicated bytes are in fact 'freed up' space: so we can make the sws_bytes larger,
         * this is always true here luxury-mode or not */
        gen_info->add_sws_bytes += accepted_bytes;

        /* buffer was returned to us so it is no longer pending return...if we increased the 'pending' we have
         * to decrease */
        if (gen_buf->flags & GEN_FLAG_SWS_UPDATE) {
            gen_info->pending_return_indications--;
            gen_info->pending_indicated_bytes-=gen_buf->ind_bytes;
        }
        mm_atomic_inc(&pdev->toe_info.stats.total_indicated_returned); /* stats */
        
        /* return buffers that were fully indicated to the generic pool, ones that we're not, to the peninsula */
        while (accepted_bytes) {
            nbytes = ((lm_tcp_gen_buf_t *)curr_gen_buf)->placed_bytes - gen_info->first_buf_offset;
            if (accepted_bytes >= nbytes) {
                /* the buffer was completely accepted */
                accepted_bytes -= nbytes;
                ret_buf = curr_gen_buf;
                curr_gen_buf = NEXT_GEN_BUF(curr_gen_buf);
                d_list_push_tail(&return_to_pool_list, &ret_buf->link);
                gen_info->num_buffers_indicated++;
                gen_info->first_buf_offset = 0;
            } else {
                gen_info->first_buf_offset += (u16_t)accepted_bytes;
                accepted_bytes = 0;
            }
        }

        /* is there anything to return to the peninsula ? (i.e. return_head moved) */
        while (curr_gen_buf) {
            curr_gen_buf->ind_bytes = 0;
            curr_gen_buf->ind_nbufs = 0;
            ret_buf = curr_gen_buf;
            curr_gen_buf = NEXT_GEN_BUF(curr_gen_buf);
            gen_info->bufs_indicated_rejected++;
            d_list_push_tail(&return_to_peninsula_list, &ret_buf->link);
        }

        if (!d_list_is_empty(&return_to_pool_list)) {
            lm_tcp_return_list_of_gen_bufs(pdev, tcp, &return_to_pool_list, MM_TCP_RGB_COMPENSATE_GRQS, NON_EXISTENT_SB_IDX);
        }
                    
        /* There must be at least something to return to the peninsula since this was partial indication */
        DbgBreakIf(d_list_is_empty(&return_to_peninsula_list));
        /* re-insert generic buffers to the peninsula.
         * we need to re-insert the buffers to the head of the peninsula */
        d_list_add_head(&gen_info->peninsula_list, &return_to_peninsula_list);
        
    } 

}

/** Description
 * returns the buffers to the generic pool
 */
void lm_tcp_return_gen_bufs(struct _lm_device_t * pdev, lm_tcp_state_t * tcp, lm_tcp_gen_buf_t * gen_buf,u32_t flags, u8_t grq_idx)
{
    lm_tcp_gen_buf_t * curr_gen_buf = gen_buf;

    #if DBG
    gen_buf->ind_nbufs = 0; /* for debugging purposes will count how many buffers are in our list */
    while (curr_gen_buf) {
        DbgBreakIf(SIG(curr_gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
        DbgBreakIf(END_SIG(curr_gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);
        /* We increase the bytes for both pool-buffers, and buffered-data buffers because when the OS
         * gives posted buffers the window is smaller */
        curr_gen_buf = NEXT_GEN_BUF(curr_gen_buf);
        gen_buf->ind_nbufs++;
    }
    #endif

    mm_tcp_return_gen_bufs(pdev, gen_buf,flags,grq_idx);
}

/** Description
 * returns the buffers to the generic pool
 */
void lm_tcp_return_list_of_gen_bufs(struct _lm_device_t * pdev, lm_tcp_state_t * tcp, d_list_t * gen_buf_list,u32_t flags, u8_t grq_idx)
{
    lm_tcp_gen_buf_t * gen_buf = (lm_tcp_gen_buf_t *)d_list_peek_head(gen_buf_list);
    lm_tcp_gen_buf_t * curr_gen_buf = gen_buf;

    #if DBG
    gen_buf->ind_nbufs = 0; /* for debugging purposes will count how many buffers are in our list */
    while (curr_gen_buf) {
        DbgBreakIf(SIG(curr_gen_buf->buf_virt) != L4GEN_BUFFER_SIG);
        DbgBreakIf(END_SIG(curr_gen_buf->buf_virt, LM_TCP_GEN_BUF_SIZE(pdev)) != L4GEN_BUFFER_SIG_END);
        /* We increase the bytes for both pool-buffers, and buffered-data buffers because when the OS
         * gives posted buffers the window is smaller */
        curr_gen_buf = NEXT_GEN_BUF(curr_gen_buf);
        gen_buf->ind_nbufs++;
    }
    #endif

    mm_tcp_return_list_of_gen_bufs(pdev, gen_buf_list,flags,grq_idx);
}

void lm_tcp_rx_indication_returned(struct _lm_device_t *pdev, lm_tcp_state_t * tcp, lm_tcp_gen_buf_t * gen_buf)
{
    DbgMessage(pdev, VERBOSEl4rx, "###lm_tcp_rx_con_indication_returned cid=%d\n", tcp->cid);

    DbgBreakIf(tcp != gen_buf->tcp);
    DbgBreakIf(tcp->cid && (tcp != lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, tcp->cid)));

    /* TBA fix in case of RcvIndicateSize > 0 */
    DbgBreakIf(gen_buf->refcnt != 0);

    tcp->rx_con->u.rx.gen_info.pending_return_indications--;
    tcp->rx_con->u.rx.gen_info.pending_indicated_bytes -= gen_buf->ind_bytes;
    
    /* Update the sws bytes according to the ind number of bytes this function is only called if in fact
     * this is a buffer that is marked as an 'update buffer' otherwise this function isn't called.  */
    DbgBreakIfAll(!(gen_buf->flags & GEN_FLAG_SWS_UPDATE));
    lm_tcp_rx_post_sws(pdev, tcp, tcp->rx_con, gen_buf->ind_bytes, TCP_RX_POST_SWS_INC);
    lm_tcp_return_gen_bufs(pdev, tcp, gen_buf, MM_TCP_RGB_COMPENSATE_GRQS, NON_EXISTENT_SB_IDX);
}

u8_t lm_tcp_is_tcp_dead(struct _lm_device_t * pdev, lm_tcp_state_t * tcp, u8_t op)
{
    UNREFERENCED_PARAMETER_(pdev);

    if(op == TCP_IS_DEAD_OP_UPLD_COMP) {
        DbgBreakIf(tcp->hdr.status != STATE_STATUS_UPLOAD_PENDING);
        tcp->hdr.status = STATE_STATUS_UPLOAD_DONE;
    }
    if (GET_FLAGS(tcp->rx_con->flags, TCP_COMP_DEFERRED)) {
        /* we can't kill the connection here! it's still being handled by deferred function which will
         * access it... killing will be done from that context... */
        return FALSE;
    }
    if (tcp->rx_con->u.rx.gen_info.pending_return_indications == 0) {
        /* If the function is called from offload completion flow, we might have completions on the RCQ 
           that we haven't processed yet so haven't completed / indicated bufs,
           so there are bytes in the peninsula and this state is legal */
        DbgBreakIf(!(tcp->rx_con->flags & TCP_RX_IND_BLOCKED) && 
                    (tcp->rx_con->u.rx.gen_info.peninsula_nbytes != 0) &&
                    (op != TCP_IS_DEAD_OP_OFLD_COMP_DFRD));
        if (tcp->hdr.status == STATE_STATUS_UPLOAD_DONE) {
            return TRUE;
        }
    }
    return FALSE;
}

lm_status_t lm_tcp_con_status(struct _lm_device_t * pdev, lm_tcp_con_t * rx_con)
{
    UNREFERENCED_PARAMETER_(pdev);

    if (rx_con->flags & TCP_RX_POST_BLOCKED) {
        return LM_STATUS_CONNECTION_CLOSED;
    }
    return LM_STATUS_SUCCESS;
}

u32_t lm_tcp_calc_gen_buf_size(struct _lm_device_t * pdev)
{
    u32_t       gen_buf_size = 0;
    u32_t const chain_idx    = LM_SW_LEADING_RSS_CID(pdev);

    /* determine size of buffer: in steps of pages, larger than the minimum and
     * the mtu */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->params.l2_cli_con_params) <= chain_idx) ||
              (CHIP_IS_E1H(pdev) && (chain_idx >= ETH_MAX_RX_CLIENTS_E1H)) || /* TODO E2 add IS_E2*/
              (CHIP_IS_E1(pdev) && (chain_idx >= ETH_MAX_RX_CLIENTS_E1)) ))
    {
        DbgBreakIf(1);
        return 0;
    }

    if (pdev->params.l4_gen_buf_size < pdev->params.l2_cli_con_params[chain_idx].mtu)
    {
        gen_buf_size = pdev->params.l2_cli_con_params[chain_idx].mtu;

    }
    else
    {
        gen_buf_size = pdev->params.l4_gen_buf_size;
    }
    /* bring to page-size boundary */
    gen_buf_size = (gen_buf_size + (LM_PAGE_SIZE-1)) & ~(LM_PAGE_SIZE-1);
    
    return gen_buf_size;
}

u16_t lm_squeeze_rx_buffer_list(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u16_t                 adjust_number,
    lm_tcp_gen_buf_t   ** unwanted_gen_buf
    )
{    
    u32_t                      gen_buff_size         = lm_tcp_calc_gen_buf_size(pdev);
    lm_tcp_con_t             * rx_con                =  tcp->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info              = &rx_con->u.rx.gen_info;
    d_list_t                   unwanted_list         = {0};
    lm_tcp_gen_buf_t         * gen_buf_copy_to       = NULL;
    lm_tcp_gen_buf_t         * gen_buf_copy_from     = NULL, *next_buffer   = NULL;
    u16_t                      free_bytes_to_copy    = 0,     bytes_to_copy = 0, gen_buf_offset = 0;
    u8_t                       force_buffer_division = FALSE;
    u16_t                      buffers_number        = (u16_t)d_list_entry_cnt(&gen_info->peninsula_list);

    *unwanted_gen_buf = NULL;   

    if ((adjust_number * gen_buff_size) >= gen_info->peninsula_nbytes) {
        d_list_init(&unwanted_list, NULL, NULL, 0);
        gen_buf_copy_to = (lm_tcp_gen_buf_t*)d_list_peek_head(&gen_info->peninsula_list);
        next_buffer = NEXT_GEN_BUF(gen_buf_copy_to);
        free_bytes_to_copy = gen_buff_size - gen_buf_copy_to->placed_bytes;
        while (buffers_number > adjust_number) {
            gen_buf_copy_from = next_buffer;
            if (gen_buf_copy_from != NULL) {
                next_buffer = NEXT_GEN_BUF(gen_buf_copy_from);
                bytes_to_copy = gen_buf_copy_from->placed_bytes;
                if (bytes_to_copy <= free_bytes_to_copy) {
                    mm_memcpy(gen_buf_copy_to->buf_virt + gen_buf_copy_to->placed_bytes, 
                              gen_buf_copy_from->buf_virt, bytes_to_copy);
                    free_bytes_to_copy -= bytes_to_copy;
                    gen_buf_copy_to->placed_bytes += bytes_to_copy;
                    d_list_remove_entry(&gen_info->peninsula_list, &gen_buf_copy_from->link);
                    d_list_push_tail(&unwanted_list, &gen_buf_copy_from->link);
                    buffers_number--;
                    continue;
                } else {
                    if (force_buffer_division) {
                        if (free_bytes_to_copy) {
                            mm_memcpy(gen_buf_copy_to->buf_virt + gen_buf_copy_to->placed_bytes, 
                                      gen_buf_copy_from->buf_virt, free_bytes_to_copy);
                            gen_buf_copy_to->placed_bytes += free_bytes_to_copy;
                            mm_memcpy(gen_buf_copy_from->buf_virt,
                                      gen_buf_copy_from->buf_virt + free_bytes_to_copy, bytes_to_copy - free_bytes_to_copy);
                            gen_buf_copy_from->placed_bytes -= free_bytes_to_copy;
                        }
                    }
                    gen_buf_copy_to = gen_buf_copy_from;
                    next_buffer = NEXT_GEN_BUF(gen_buf_copy_from);
                    free_bytes_to_copy = gen_buff_size - gen_buf_copy_to->placed_bytes;
                    continue;
                }
            } else {
                if (!force_buffer_division) {
                    force_buffer_division = TRUE;
                    gen_buf_copy_to = (lm_tcp_gen_buf_t*)d_list_peek_head(&gen_info->peninsula_list);
                    next_buffer = NEXT_GEN_BUF(gen_buf_copy_to);
                    gen_buf_offset = gen_info->first_buf_offset;
                    if (gen_buf_offset) {
                        /* move to start of buffer*/
                        mm_memcpy(gen_buf_copy_to->buf_virt, 
                                  gen_buf_copy_to->buf_virt + gen_buf_offset, gen_buf_copy_to->placed_bytes - gen_buf_offset);
                        gen_buf_copy_to->placed_bytes -= gen_buf_offset;
                        gen_buf_offset = gen_info->first_buf_offset = 0;
                    }
                    free_bytes_to_copy = gen_buff_size - gen_buf_copy_to->placed_bytes;
                    continue;
                } else {
                    DbgMessage(pdev, WARNl4rx | WARNl4sp,
                                "###lm_squeeze_rx_buffer_list cid=%d: peninsula_list cnt (%d) is still more frag_count (%d)\n",
                                tcp->cid, buffers_number, adjust_number);
                    break;
                }
            }
        }
        *unwanted_gen_buf = (lm_tcp_gen_buf_t*)d_list_peek_head(&unwanted_list);
        DbgMessage(pdev, WARNl4rx | WARNl4sp,
                    "###lm_squeeze_rx_buffer_list cid=%d(%d,%d,%d): peninsula_list cnt is decreased till %d\n",
                    tcp->cid, tcp->tcp_cached.initial_rcv_wnd, tcp->tcp_cached.rcv_indication_size, gen_buff_size, buffers_number);
    } else {
        DbgMessage(pdev, WARNl4rx | WARNl4sp,
                    "###lm_squeeze_rx_buffer_list cid=%d(%d,%d): could not replace %dB (%d bufs) into %d frags of %dB each\n",
                    tcp->cid, tcp->tcp_cached.initial_rcv_wnd, tcp->tcp_cached.rcv_indication_size, 
                    gen_info->peninsula_nbytes, buffers_number, adjust_number, gen_buff_size);
    }
    return  buffers_number;
}

void lm_tcp_rx_clear_isles(struct _lm_device_t * pdev, lm_tcp_state_t * tcp_state, d_list_t * isles_list)
{
    lm_tcp_con_rx_gen_info_t * gen_info;
    u8_t        isle_cnt;

    DbgBreakIf(!(tcp_state && tcp_state->rx_con));
    gen_info = &tcp_state->rx_con->u.rx.gen_info;
    while ((isle_cnt = (u8_t)d_list_entry_cnt(&gen_info->isles_list))) {
        d_list_t aux_isles_list;
        d_list_init(&aux_isles_list, NULL, NULL, 0);
        _lm_tcp_isle_remove(pdev, tcp_state, NON_EXISTENT_SB_IDX, isle_cnt, &aux_isles_list);
        if (!d_list_is_empty(&aux_isles_list)) {
        d_list_add_head(isles_list, &aux_isles_list);
    }
    }
    return;
}

