
#include "lm5710.h"
#include "bd_chain.h"
#include "command.h"
#include "context.h"
#include "lm_l4fp.h"
#include "lm_l4sp.h"
#include "mm_l4if.h"


/* TODO: remove this temporary solution for solaris / linux compilation conflict, linux needs the
 * first option, solaris the latter */
#if defined(__LINUX)
#define TOE_TX_INIT_ZERO {{0}}
#else
#define TOE_TX_INIT_ZERO {0}
#endif

#define TOE_TX_DOORBELL(pdev,cid) do{\
    struct doorbell db = TOE_TX_INIT_ZERO;\
    db.header.data |= (TOE_CONNECTION_TYPE << DOORBELL_HDR_T_CONN_TYPE_SHIFT);\
    DOORBELL((pdev), (cid), *((u32_t *)&db));\
    } while(0)

static __inline void _lm_tcp_tx_write_db(
    lm_device_t  * pdev,
    lm_tcp_con_t * tx_con,
    u32_t cid,
    u32_t nbytes,
    u16_t nbds,
    u8_t fin)
{
    volatile struct toe_tx_db_data *db_data = tx_con->db_data.tx;
    
    db_data->bds_prod += nbds;       /* nbds should be written before nbytes (FW assumption) */
    DbgBreakIf((db_data->bds_prod & 0xff) == 0);
    db_data->bytes_prod_seq += nbytes;        

    if(fin) {
        DbgBreakIf(db_data->flags & (TOE_TX_DB_DATA_FIN << TOE_TX_DB_DATA_FIN_SHIFT));
        db_data->flags |= (TOE_TX_DB_DATA_FIN << TOE_TX_DB_DATA_FIN_SHIFT);
    }

    if (!(tx_con->flags & TCP_TX_DB_BLOCKED)) {
        DbgMessage(pdev, INFORMl4tx,
                    "ringing tx doorbell: cid=%d, (nbytes+=%d, nbds+=%d, fin=%d)\n", 
                    cid, nbytes, nbds, fin);
        TOE_TX_DOORBELL(pdev, cid);    
    }
}

static __inline void lm_tcp_tx_write_db(
    lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    u8_t post_end)
{
    lm_tcp_con_t *tx_con = tcp->tx_con;

    /* define a policy for ringing the doorbell */
    #define MAX_BYTES_PER_TX_DB    0xffff
    #define MAX_BDS_PER_TX_DB      64

    if (post_end || 
        tx_con->db_more_bytes >= MAX_BYTES_PER_TX_DB ||
        tx_con->db_more_bds >= MAX_BDS_PER_TX_DB) {
        _lm_tcp_tx_write_db(pdev, tx_con, tcp->cid, tx_con->db_more_bytes, tx_con->db_more_bds, 0); 
        
        /* assert if the new addition will make the cyclic counter post_cnt smaller than comp_cnt */
        DbgBreakIf(S64_SUB(tx_con->bytes_post_cnt + tx_con->db_more_bytes, tx_con->bytes_comp_cnt) < 0);
        tx_con->bytes_post_cnt += tx_con->db_more_bytes;
        tx_con->buffer_post_cnt += tx_con->db_more_bufs;
        tx_con->db_more_bytes = tx_con->db_more_bds = tx_con->db_more_bufs = 0;       
        tx_con->fp_db_cnt++;
    } else {
        DbgMessage(pdev, INFORMl4tx,
                    "skipped doorbell ringing for cid=%d\n", tcp->cid);
    }   
}

/** Description:
 *  Post a single tcp buffer to the Tx bd chain
 * Assumptions:
 *  - caller initiated tcp_buf->flags field with BUFFER_START/BUFFER_END appropriately
 * Returns:
 *  - SUCCESS - tcp buf was successfully attached to the bd chain
 *  - RESOURCE - not enough available BDs on bd chain for given tcp buf
 *  - CONNECTION_CLOSED - whenever connection's flag are marked as 'POST BLOCKED' */
lm_status_t lm_tcp_tx_post_buf(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_buffer_t     *tcp_buf,
    lm_frag_list_t      *frag_list)
{
    lm_tcp_con_t *tx_con;
    lm_bd_chain_t *tx_chain;
    struct toe_tx_bd *tx_bd = NULL ;
    lm_frag_t *frag;
    u32_t i, dbg_buf_size = 0;
    u32_t dbg_bytes_prod_seq;
    u16_t old_prod, new_prod;

    DbgMessage(pdev, VERBOSEl4tx, "###lm_tcp_tx_post_buf\n");
    DbgBreakIf(!(pdev && tcp && tcp_buf && frag_list));
    DbgBreakIf(tcp->cid && (tcp != lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, tcp->cid)));
    DbgBreakIf(frag_list->cnt == 0);
    tx_con = tcp->tx_con;
    tx_chain = &tx_con->bd_chain;
    frag = frag_list->frag_arr;

    DbgBreakIf(tx_con->flags & TCP_FIN_REQ_POSTED);

    /* check if tx con is already closed */
    if(tx_con->flags & TCP_TX_POST_BLOCKED) {
        DbgMessage(pdev, WARNl4tx, "post tx buf failed, posting is blocked (cid=%d, con->flags=%x)\n",
                    tcp->cid, tx_con->flags);
        return LM_STATUS_CONNECTION_CLOSED;
    }       
    /* check bd chain availability (including additional bd that should
     * be kept available for future fin request) */
    if(lm_bd_chain_avail_bds(tx_chain) < frag_list->cnt + 1) {
        DbgMessage(pdev, INFORMl4tx, "post tx buf failed, tx chain is full (cid=%d, avail bds=%d, buf nfrags=%d)\n",
                    tcp->cid, lm_bd_chain_avail_bds(tx_chain), frag_list->cnt);

        LM_COMMON_DRV_STATS_ATOMIC_INC_TOE(pdev, tx_no_l4_bd);

        if (tx_con->db_more_bds) {
            /* if doorbell ringing was deferred (e.g. until an end of 
             * application buffer), it can no longer be deferred since 
             * the place in the bd chain is now required */
            lm_tcp_tx_write_db(pdev, tcp, 1);
        }
        return LM_STATUS_RESOURCE; 
    }

    old_prod = lm_bd_chain_prod_idx(tx_chain);

    dbg_bytes_prod_seq = tx_con->db_data.tx->bytes_prod_seq + tx_con->db_more_bytes;
     /* "attach" the frags to the bd chain */
    for(i = 0; i < frag_list->cnt; i++, frag++) {
        DbgBreakIf(frag->size > 0xffff || frag->size == 0); /* hw limit: each bd can point to a buffer with max size of 64KB */
        tx_bd = (struct toe_tx_bd *)lm_toe_bd_chain_produce_bd(tx_chain);
        tx_bd->addr_hi = frag->addr.as_u32.high;
        tx_bd->addr_lo = frag->addr.as_u32.low;
        tx_bd->flags = 0;
        tx_bd->size = (u16_t)frag->size;                
        dbg_bytes_prod_seq += frag->size;
        tx_bd->nextBdStartSeq = dbg_bytes_prod_seq;
        dbg_buf_size += frag->size;

        /* Support for FW Nagle Algorithm: 
         * This bit, is to be set for every bd which is part of a tcp buffer which is equal to or larger than an mss.
         */
        if ((u32_t)frag_list->size >= tx_con->u.tx.mss) {
            tx_bd->flags |= TOE_TX_BD_LARGE_IO;
        }

        DbgMessage(pdev, VERBOSEl4tx, "Setting Tx BD, addr_lo=0x%x, addr_hi=0x%x, size=%d\n",
                    tx_bd->addr_lo, tx_bd->addr_hi, tx_bd->size);
    }

    DbgBreakIf(frag_list->cnt > 0xffff);
    tcp_buf->bd_used = frag_list->cnt & 0xffff;
    tcp_buf->size = tcp_buf->more_to_comp = (u32_t)frag_list->size;
    DbgBreakIf(tcp_buf->size != dbg_buf_size);

    DbgBreakIf(!(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_START ?
                 tx_con->app_buf_bytes_acc_post == 0 :
                 tx_con->app_buf_bytes_acc_post > 0));
    tx_con->app_buf_bytes_acc_post += tcp_buf->size;    
    tx_con->db_more_bytes += tcp_buf->size;
    new_prod = lm_bd_chain_prod_idx(tx_chain);
    DbgBreakIf(S16_SUB(new_prod, old_prod) < tcp_buf->bd_used);
    tx_con->db_more_bds += S16_SUB(new_prod, old_prod);
    tx_con->db_more_bufs++;

    /* Support for FW Nagle Algorithm: 
     * This bit, is to be set for every bd which is part of a tcp buffer which is equal to or larger than an mss.
     */
    if (tcp_buf->size >= tx_con->u.tx.mss) {
        tx_bd->flags |= TOE_TX_BD_LARGE_IO;
    }

    /* special care in case of last tcp buffer of an application buffer */
    if(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END) {
        tcp_buf->app_buf_xferred = 0; /* just for safety */
        tcp_buf->app_buf_size = tx_con->app_buf_bytes_acc_post;
        tx_con->app_buf_bytes_acc_post = 0;

        /* special care for the last bd: */
        tx_bd->flags |= TOE_TX_BD_NOTIFY;
        tx_con->u.tx.bds_without_comp_flag = 0;        
        tx_bd->flags |= TOE_TX_BD_PUSH;   

        DbgMessage(pdev, VERBOSEl4tx,
                    "Setting Tx BD, last bd of app buf, flags=%d\n", tx_bd->flags);
    } else {      
        /* make sure there aren't 'too many' bds without completion flag */
        tx_con->u.tx.bds_without_comp_flag += tcp_buf->bd_used;
        if (tx_con->u.tx.bds_without_comp_flag > (tx_chain->capacity - MAX_FRAG_CNT_PER_TB)) {
            tx_bd->flags |= TOE_TX_BD_NOTIFY;
            tx_con->u.tx.bds_without_comp_flag = 0;
        }
    }

    s_list_push_tail(&tx_con->active_tb_list, &tcp_buf->link);
    tx_con->rq_nbytes += tcp_buf->size;
    lm_tcp_tx_write_db(pdev, tcp, tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END);

    /* network reachability (NOT IMPLEMENTED): 
    if(lm_neigh_is_cache_entry_staled(tcp->path->neigh))
       lm_neigh_indicate_staled_cache_entry(tcp->path->neigh);
    */

    DbgMessage(pdev, VERBOSEl4tx, "posted tx buf for cid=%d, buf size=%d, bd used=%d, buf flags=%x, app_buf_size=%d\n",
                tcp->cid, tcp_buf->size, tcp_buf->bd_used, tcp_buf->flags, tcp_buf->app_buf_size);
    DbgMessage(pdev, VERBOSEl4tx, "after posting tx buf, tx_con->active_tb_list=%d\n",
                s_list_entry_cnt(&tx_con->active_tb_list));    

    return LM_STATUS_SUCCESS;
} /* lm_tcp_tx_post_buf */

/** Description
 *  indicates graceful disconnect completion to client.
 * Assumtpions:
 *  tx-lock is taken by caller 
 */ 
static __inline void lm_tcp_tx_graceful_disconnect_complete(lm_device_t * pdev, lm_tcp_state_t * tcp)
{
    u8_t ip_version;
    DbgBreakIf(!s_list_is_empty(&tcp->tx_con->active_tb_list));
    DbgBreakIf(tcp->tx_con->flags & TCP_FIN_REQ_COMPLETED);
    tcp->tx_con->flags |= TCP_FIN_REQ_COMPLETED;
    DbgMessage(pdev, INFORMl4tx, "fin request completed (cid=%d)\n", tcp->cid);
    tcp->tcp_state_calc.fin_completed_time = mm_get_current_time(pdev); 
    if (!(tcp->tx_con->u.tx.flags & TCP_CON_FIN_REQ_LM_INTERNAL)) {
        ip_version = (tcp->path->path_const.ip_version == IP_VERSION_IPV4)? STATS_IP_4_IDX : STATS_IP_6_IDX;
        LM_COMMON_DRV_STATS_ATOMIC_INC_TOE(pdev, ipv[ip_version].out_fin);
        mm_tcp_graceful_disconnect_done(pdev,tcp, LM_STATUS_SUCCESS); 
    }
}

void lm_tcp_tx_cmp_process(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    u32_t               completed_bytes
    )
{
    lm_tcp_con_t *tx_con = tcp->tx_con;
    u32_t actual_completed; /* number of bytes actually completed (could be different than completed in case of fin) */
    MM_INIT_TCP_LOCK_HANDLE();
    
    DbgMessage(pdev, VERBOSEl4tx, "##lm_tcp_tx_app_cmp_process, cid=%d, completed_bytes=%d\n",
                tcp->cid, completed_bytes);

    DbgBreakIf(tx_con->flags & TCP_TX_COMP_BLOCKED);

    if (!(tx_con->flags & TCP_DEFERRED_PROCESSING)) {
        mm_acquire_tcp_lock(pdev, tx_con);
    }
    tx_con->bytes_comp_cnt += completed_bytes;
    DbgBreakIf(S64_SUB(tx_con->bytes_post_cnt, tx_con->bytes_comp_cnt) < 0);

    DbgBreakIf(!completed_bytes);

    actual_completed = lm_tcp_complete_nbytes(pdev, tcp, tcp->tx_con, completed_bytes, FALSE);

    if (actual_completed != completed_bytes) {
        DbgBreakIf(actual_completed > completed_bytes);
        DbgBreakIf((completed_bytes - actual_completed) != 1);
        DbgBreakIf(!(tx_con->flags & TCP_FIN_REQ_POSTED));
        DbgBreakIf(tx_con->bytes_post_cnt != tx_con->bytes_comp_cnt);
        /* fin completed */
        tx_con->dpc_info.dpc_flags |= LM_TCP_DPC_FIN_CMP;
        tx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_FIN_REQ_COMPLETED */
    }

    /* network reachability (NOT IMPLEMENTED): 
    lm_neigh_update_nic_reachability_time(tcp->path->neigh)
    */
    if (!(tx_con->flags & TCP_DEFERRED_PROCESSING)) {
        mm_release_tcp_lock(pdev, tx_con);
    }

} /* lm_tcp_tx_app_cmp_process */

u8_t lm_toe_is_tx_completion(lm_device_t *pdev, u8_t drv_toe_rss_id)
{
    u8_t result = FALSE;
    lm_tcp_scq_t *scq = NULL;
    
    DbgBreakIf(!(pdev && ARRSIZE(pdev->toe_info.scqs) > drv_toe_rss_id));

    scq = &pdev->toe_info.scqs[drv_toe_rss_id];
    
    if ( scq->hw_con_idx_ptr && 
        *scq->hw_con_idx_ptr != lm_bd_chain_cons_idx(&scq->bd_chain) )
    {
        result = TRUE;
    }
    DbgMessage(pdev, INFORMl4int, "lm_toe_is_tx_completion(): result is:%s\n", result? "TRUE" : "FALSE");

    return result;
}

void lm_tcp_tx_inc_trm_aborted_bytes(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    u32_t               aborted_bytes
    )
{
    lm_tcp_con_t *tx_con = tcp->tx_con;
    MM_INIT_TCP_LOCK_HANDLE();
    
    DbgMessage(pdev, VERBOSEl4tx, "##lm_tcp_tx_inc_aborted_count, cid=%d, aborted_bytes=%d\n",
                tcp->cid, aborted_bytes);

    if (!(tx_con->flags & TCP_DEFERRED_PROCESSING)) {
        mm_acquire_tcp_lock(pdev, tx_con);
    }

    tx_con->bytes_trm_aborted_cnt += aborted_bytes;

    if (!(tx_con->flags & TCP_DEFERRED_PROCESSING)) {
        mm_release_tcp_lock(pdev, tx_con);
    }

} /* lm_tcp_tx_inc_aborted_count */

/** Description
 *   completes the fast-path operations for a certain connection
 *  Assumption: 
 *   fp-tx lock is taken
 */ 
void lm_tcp_tx_complete_tcp_fp(lm_device_t * pdev, lm_tcp_state_t * tcp, lm_tcp_con_t * con)
{
    /**** Client completing :  may result in lock-release *****/
    /* during lock-release, due to this function being called from service_deferred, more
     * cqes can be processed. We don't want to mix. This function is mutually exclusive, so 
     * any processing makes it's way to being completed by calling this function.
     * the following define a "fast-path completion"
     * (i)   RQ buffers to be completed
     *       defined by dpc_completed_tail and are collected during lm_tcp_complete_bufs BEFORE lock
     *       is released, so no more buffer processing can make it's way into this buffer completion.
     * (ii)  Fin to be completed
     *       determined by the flags, since dpc_flags CAN be modified during processing we copy
     *       them to a snapshot_flags parameter, which is initialized in this function only, so no fin
     *       can can make its way in while we release the lock.
     * (iv)  Remainders for sp
     *       all sp operations are logged in dpc_flags. for the same reason as (iii) no sp commands can 
     *       make their way in during this fp-completion, all sp-processing after will relate to this point in time.
     */

    con->dpc_info.snapshot_flags = con->dpc_info.dpc_flags;
    con->dpc_info.dpc_flags = 0;

    /* complete buffers to client */
    if (con->dpc_info.dpc_completed_tail != NULL) {
        lm_tcp_complete_bufs(pdev, tcp, con);
    }
    
    /* Graceful Disconnect */
    if (con->dpc_info.snapshot_flags & LM_TCP_DPC_FIN_CMP) {
        con->dpc_info.snapshot_flags &= ~LM_TCP_DPC_FIN_CMP;
        lm_tcp_tx_graceful_disconnect_complete(pdev, con->tcp_state);
    }

}

void lm_tcp_tx_process_cqe(
    lm_device_t        * pdev, 
    struct toe_tx_cqe  * cqe, 
    lm_tcp_state_t     * tcp
    )
{
    enum toe_sq_opcode_type cmd;

    /* get the cmd from cqe */
    cmd = ((cqe->params & TOE_TX_CQE_COMPLETION_OPCODE) >> TOE_TX_CQE_COMPLETION_OPCODE_SHIFT);

    DbgMessage(pdev, INFORMl4tx, "###lm_tcp_tx_process_cqe cid=%d cmd=%d\n", tcp->cid, cmd);
    DbgBreakIf( ! (pdev && tcp) );
    /* Check that the cqe len make sense, we could have got here by chance... */
    DbgBreakIfAll(cqe->len & 0xc0000000); /* two upper bits on show a completion larger than 1GB - a bit odd...*/

    /* Three types of completios: fast-path, reset-recv, ramrod-cmp. All completions may have a 
     * fast-path part (nbytes completed) which will be handled in any case that cqe->len > 0 */

    /* complete data if anything needs to be complete */    
    if (cqe->len &&
        ((tcp->tx_con->dpc_info.dpc_flags & LM_TCP_DPC_RESET_RECV /* RST recv on this DPC on a previous CQE */ ) ||
         (tcp->tx_con->flags & TCP_REMOTE_RST_RECEIVED /* RST recv on previous DPC */ )))
    {    
        /* 10/28/08 - Since in exterme cases current FW may not complete all sent+acked bytes 
           on RST recv cqe and do so only later on one of the following ramrod completions, 
           we need to ignore this too late completed bytes thus we nullify cqe->len */
        DbgBreakIf((cmd != RAMROD_OPCODE_TOE_RESET_SEND) &&
                   (cmd != RAMROD_OPCODE_TOE_INVALIDATE) &&
                   (cmd != RAMROD_OPCODE_TOE_EMPTY_RAMROD) &&
                   (cmd != RAMROD_OPCODE_TOE_TERMINATE));
        lm_tcp_tx_inc_trm_aborted_bytes(pdev, tcp, cqe->len);
        cqe->len = 0;
    }
    if (cqe->len) {
        DbgBreakIf(tcp->tx_con->dpc_info.dpc_comp_blocked);
        lm_tcp_tx_cmp_process(pdev, tcp, cqe->len);
    }

    switch(cmd) {
    case CMP_OPCODE_TOE_TX_CMP:
        break;
    case CMP_OPCODE_TOE_RST_RCV:
        tcp->tx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RESET_RECV;
        tcp->tx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_REMOTE_RST_RECEIVED */
        break;
    case RAMROD_OPCODE_TOE_RESET_SEND:
        DbgBreakIf(! tcp->sp_request);
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_ABORTIVE_DISCONNECT);
        tcp->tx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        tcp->tx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_RST_REQ_COMPLETED */
        break;
    case RAMROD_OPCODE_TOE_INVALIDATE:
        DbgBreakIf(! tcp->sp_request);
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_INVALIDATE);
        tcp->tx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        tcp->tx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_INV_REQ_COMPLETED */
        break;
    case RAMROD_OPCODE_TOE_TERMINATE:
        DbgBreakIf(! tcp->sp_request);
        DbgBreakIf(tcp->sp_request->type != SP_REQUEST_TERMINATE1_OFFLOAD);
        tcp->tx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        tcp->tx_con->dpc_info.dpc_comp_blocked = TRUE; /* TCP_TRM_REQ_COMPLETED */
        break;
    case RAMROD_OPCODE_TOE_EMPTY_RAMROD:
        DbgBreakIf(cqe->len);
        DbgBreakIf(! tcp->sp_request );
        DbgBreakIf((tcp->sp_request->type != SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT) &&
                   (tcp->sp_request->type != SP_REQUEST_PENDING_REMOTE_DISCONNECT) &&
                   (tcp->sp_request->type != SP_REQUEST_PENDING_TX_RST));
        tcp->tx_con->dpc_info.dpc_flags |= LM_TCP_DPC_RAMROD_CMP;
        break;
    default:
        DbgMessage(pdev, FATAL, "unexpected tx cqe opcode=%d\n", cmd);
        DbgBreakIfAll(TRUE);
    }
}

/** Description
 * 
 * Assumptions
 *   connections is initialzed with a dummy head.
 */ 
void lm_tcp_tx_process_cqes(lm_device_t *pdev, u8_t drv_toe_rss_id, s_list_t * connections)
{
    lm_tcp_scq_t *scq;
    struct toe_tx_cqe *cqe, *hist_cqe;
    lm_tcp_state_t *tcp;
    u32_t cid;    
    u32_t avg_dpc_cnt;
    u16_t cq_new_idx;
    u16_t cq_old_idx;
    u16_t num_to_reproduce = 0;
    u8_t defer_cqe;
    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4int , "###lm_tcp_tx_process_cqes\n");
    
    scq = &pdev->toe_info.scqs[drv_toe_rss_id];
    cq_new_idx = *(scq->hw_con_idx_ptr);
    cq_old_idx = lm_bd_chain_cons_idx(&scq->bd_chain);
    DbgBreakIf(S16_SUB(cq_new_idx, cq_old_idx) <= 0);     

    /* save statistics */
    scq->num_cqes_last_dpc = S16_SUB(cq_new_idx, cq_old_idx);
    if (scq->num_cqes_last_dpc) { /* Exclude zeroed value from statistics*/
        if(scq->max_cqes_per_dpc < scq->num_cqes_last_dpc) {
            scq->max_cqes_per_dpc = scq->num_cqes_last_dpc;
        }
        /* we don't want to wrap around...*/
        if ((scq->sum_cqes_last_x_dpcs + scq->num_cqes_last_dpc) < scq->sum_cqes_last_x_dpcs) {
            scq->avg_dpc_cnt = 0;
            scq->sum_cqes_last_x_dpcs = 0;
        }
        scq->sum_cqes_last_x_dpcs += scq->num_cqes_last_dpc;
        scq->avg_dpc_cnt++;
        avg_dpc_cnt = scq->avg_dpc_cnt;
        if (avg_dpc_cnt) {
            scq->avg_cqes_per_dpc = scq->sum_cqes_last_x_dpcs / avg_dpc_cnt;
        } else {
            scq->sum_cqes_last_x_dpcs = 0;
        }
    }

    while(cq_old_idx != cq_new_idx) {
        DbgBreakIf(S16_SUB(cq_new_idx, cq_old_idx) <= 0);

        /* get next consumed cqe */
        cqe = lm_toe_bd_chain_consume_bd(&scq->bd_chain);
        DbgBreakIf(!cqe); 
        num_to_reproduce++;

        /* get tcp state from cqe */
        cid = SW_CID(((cqe->params & TOE_TX_CQE_CID) >> TOE_TX_CQE_CID_SHIFT));
        tcp = lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, cid);
        DbgBreakIf(!tcp);
        /* save cqe in history_cqes */
        hist_cqe = (struct toe_tx_cqe *)lm_tcp_qe_buffer_next_cqe_override(&tcp->tx_con->history_cqes);
        *hist_cqe = *cqe;
        
        defer_cqe = ((tcp->tx_con->flags & TCP_TX_COMP_DEFERRED) == TCP_TX_COMP_DEFERRED);
        if (defer_cqe) {
            /* if we're deferring completions - just store the cqe and continue to the next one */
            /* Return if we are still deferred (may have changed since initial check was w/o a lock */
            mm_acquire_tcp_lock(pdev, tcp->tx_con);
            /* check again under lock if we're deferred */
            defer_cqe = ((tcp->tx_con->flags & TCP_TX_COMP_DEFERRED) == TCP_TX_COMP_DEFERRED);
            if (defer_cqe) {
                tcp->tx_con->flags |= TCP_DEFERRED_PROCESSING;
                lm_tcp_tx_process_cqe(pdev, cqe, tcp);
            }
            mm_release_tcp_lock(pdev, tcp->tx_con);
        }
        if (!defer_cqe) {
            /* connections will always be initialized to a dummy, so once a tcp connection is added to the 
             * list, it's link will be initialized to point to another link other than NULL */
            if (s_list_next_entry(&tcp->tx_con->dpc_info.link) == NULL) {
                s_list_push_head(connections, &tcp->tx_con->dpc_info.link);
            }
            lm_tcp_tx_process_cqe(pdev, cqe, tcp);
        } 
        cq_old_idx = lm_bd_chain_cons_idx(&scq->bd_chain);
        /* GilR 5/12/2006 - TODO - decide with Alon if reading the hw_con again is required */
        //cq_new_idx = *(scq->hw_con_idx_ptr);
    }

    /* The fact that we post the producer here before we've handled any slow-path completions assures that 
     * the sp-ring will always be updated AFTER the producer was. */
    if (num_to_reproduce) {
        lm_toe_bd_chain_bds_produced(&scq->bd_chain, num_to_reproduce);
    
        /* GilR 5/13/2006 - TBA - save some stats? */

        /* notify the fw of the prod of the SCQ */
        LM_INTMEM_WRITE16(pdev, CSTORM_TOE_CQ_PROD_OFFSET(LM_TOE_FW_RSS_ID(pdev,drv_toe_rss_id) , PORT_ID(pdev)),
                          lm_bd_chain_prod_idx(&scq->bd_chain),  BAR_CSTRORM_INTMEM);
    }
}

void lm_toe_service_tx_intr(lm_device_t *pdev, u8_t drv_toe_rss_id)
{
    s_list_t         connections;
    s_list_entry_t   dummy;
    lm_tcp_con_t   * con;
    lm_tcp_state_t * tcp;

    MM_INIT_TCP_LOCK_HANDLE();

    DbgMessage(pdev, VERBOSEl4int , "###lm_toe_service_tx_intr\n");
    DbgBreakIf(!(pdev && ARRSIZE(pdev->toe_info.scqs) > drv_toe_rss_id));

    s_list_clear(&connections);
    s_list_push_head(&connections, &dummy);
    /* process the cqes and initialize connections with all the connections that appeared
     * in the DPC */
    lm_tcp_tx_process_cqes(pdev,drv_toe_rss_id,&connections);
    
    /* complete the fp/sp parts of the connections remember to ignore the last one */
    con = (lm_tcp_con_t *)s_list_peek_head(&connections);
    tcp = con->tcp_state;
    while (s_list_next_entry(&con->dpc_info.link) != NULL) {
        mm_acquire_tcp_lock(pdev, con);
        lm_tcp_tx_complete_tcp_fp(pdev, con->tcp_state, con);
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
            lm_tcp_tx_complete_tcp_sp(pdev, tcp, con);
        }
        con = (lm_tcp_con_t *)s_list_pop_head(&connections);
        s_list_next_entry(&con->dpc_info.link) = NULL;
        tcp = con->tcp_state;
    }

}

lm_status_t lm_tcp_graceful_disconnect(
    IN lm_device_t          * pdev,
    IN lm_tcp_state_t       * tcp_state
)
{
    struct toe_tx_bd *tx_bd;
    lm_tcp_con_t     *tcp_con = tcp_state->tx_con;
    u16_t old_prod, new_prod;
    u32_t dbg_bytes_prod_seq;

    DbgMessage(pdev, INFORMl4tx, "###lm_tcp_graceful_disconnect\n");
    
    if ( tcp_con->flags & TCP_TX_POST_BLOCKED ) {
        return LM_STATUS_CONNECTION_CLOSED;
    }

    DbgBreakIf( (tcp_con->app_buf_bytes_acc_post != 0) ||
                (tcp_con->db_more_bytes != 0) ||
                (tcp_con->db_more_bds != 0) ||
                (tcp_con->u.tx.bds_without_comp_flag != 0)
                );

    old_prod = lm_bd_chain_prod_idx(&(tcp_con->bd_chain));

    /* Post FIN BD on Tx chain */
    tx_bd = (struct toe_tx_bd *)lm_toe_bd_chain_produce_bd(&(tcp_con->bd_chain));
    tx_bd->flags = TOE_TX_BD_FIN;  /* Vladz: Pay attention when u move this 
                                             line - there is an assignment to flags, NOT bitwise OR */
    tx_bd->flags |= TOE_TX_BD_NOTIFY;
    tx_bd->size = 1;   
    /* For a safety */
    tx_bd->addr_hi = tx_bd->addr_lo = 0;

    dbg_bytes_prod_seq = tcp_con->db_data.tx->bytes_prod_seq + tcp_con->db_more_bytes;
    dbg_bytes_prod_seq += tx_bd->size;
    tx_bd->nextBdStartSeq = dbg_bytes_prod_seq;

    new_prod = lm_bd_chain_prod_idx(&(tcp_con->bd_chain));
    DbgBreakIf(S16_SUB(new_prod, old_prod) >= 3);
    DbgBreakIf(S16_SUB(new_prod, old_prod) <= 0);
    
    DbgBreakIf(tcp_con->flags & TCP_FIN_REQ_POSTED);
    tcp_con->flags |= TCP_FIN_REQ_POSTED;

    /* Update fin request time, if not already set by the caller */
    if (!tcp_state->tcp_state_calc.fin_request_time) {
        tcp_state->tcp_state_calc.fin_request_time = mm_get_current_time(pdev); 
        if (tcp_state->tcp_state_calc.fin_request_time == tcp_state->tcp_state_calc.fin_reception_time){
            tcp_state->tcp_state_calc.fin_reception_time -= 1;
        }
    }    

    /* Doorbell FIN */
    _lm_tcp_tx_write_db(pdev, tcp_con, tcp_state->cid, 0, (u16_t)S16_SUB(new_prod, old_prod), 1);
    
    /* assert if the new addition will make the cyclic counter post_cnt smaller than comp_cnt */
    DbgBreakIf(S64_SUB(tcp_con->bytes_post_cnt + 1, tcp_con->bytes_comp_cnt) < 0);
    tcp_con->bytes_post_cnt++;
    tcp_con->fp_db_cnt++;

    return LM_STATUS_SUCCESS;
}


