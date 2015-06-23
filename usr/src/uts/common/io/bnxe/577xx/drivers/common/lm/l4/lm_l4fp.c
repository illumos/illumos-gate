

#include "lm5710.h"
#include "bd_chain.h"
#include "lm_l4fp.h"
#include "mm_l4if.h"

/**
 * Description
 *   complete Rx and Tx application buffers to client
 * Assumption: 
 *   Called under fp-lock
 *   Called only from DPC-Flow
 */ 
void lm_tcp_complete_bufs(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_con_t        *con)
{
    s_list_t          completed_bufs;

    /* check which buffers need to be completed to client */
    s_list_clear(&completed_bufs);

    /* should only be here if we have something to complete */
    DbgBreakIf(con->dpc_info.dpc_completed_tail == NULL);
    s_list_split(&con->active_tb_list, &completed_bufs, 
                 con->dpc_info.dpc_completed_tail, con->dpc_info.dpc_bufs_completed);
    con->dpc_info.dpc_completed_tail = NULL;
    DbgBreakIf(con->rq_nbytes < con->dpc_info.dpc_actual_bytes_completed);
    con->rq_nbytes -= con->dpc_info.dpc_actual_bytes_completed;

    lm_bd_chain_bds_consumed(&con->bd_chain, con->dpc_info.dpc_bd_used);
    con->dpc_info.dpc_bd_used = 0;
    con->dpc_info.dpc_bufs_completed = 0;

    con->buffer_completed_cnt += s_list_entry_cnt(&completed_bufs);    
    DbgMessage(pdev, VERBOSEl4fp,
                "cid=%d, completing %d bufs towards mm, actual_completed_bytes=%d, %d bufs still in active tb list\n", 
                tcp->cid, s_list_entry_cnt(&completed_bufs), con->dpc_info.dpc_actual_bytes_completed, s_list_entry_cnt(&con->active_tb_list));

    con->dpc_info.dpc_actual_bytes_completed = 0;


    /* GilR 5/10/2006 - TBD - Might need some kind of indicating policy towards the mm - i.e. indicate MaxIndicationLimit at a time*/
    DbgBreakIf(s_list_is_empty(&completed_bufs));
    if (!con->rq_completion_calls) {
        lm_tcp_buffer_t     *tcp_buf = (lm_tcp_buffer_t *)s_list_peek_head(&completed_bufs);
        if (tcp_buf->flags & TCP_BUF_FLAG_L4_PARTIAL_FILLED) {
            RESET_FLAGS(con->db_data.rx->flags, TOE_RX_DB_DATA_PARTIAL_FILLED_BUF);
        }
    }
    con->rq_completion_calls++;
    mm_tcp_complete_bufs(pdev, tcp, con, &completed_bufs, LM_STATUS_SUCCESS);
}
/** Description:
 *  Complete nbytes from Tx and Rx application buffers
 * Assumptions:
 *  Called ONLY from dpc-flow (or deferred_cqes) not POST - flow
 *  Called W/O a lock (unless from deferred)
 *  push can have 3 values:
 *      - 0: no-push
 *      - 1: regular push
 *      - 2: push as a result of terminate / reset / fin... 
 * Returns:
 *  Actual bytes completed towards mm. (If push==0 this number is equal to
 *  given completed_bytes, and if push==1 it might be larger), if fin is received this
 *  may be smaller than completed_bytes by a maximum of '1' */
u32_t lm_tcp_complete_nbytes(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_con_t        *con,            /* Rx OR Tx connection */
    u32_t               completed_bytes, /* num bytes completed (might be 0) */
    u8_t                push             /* if == 0, don't complete partialy 
                                            completed buffers towards mm. If (1) - regular push, if (2) push as result of sp-completion (terminate for example) */) 
{
    lm_tcp_buffer_t * tcp_buf                = lm_tcp_next_entry_dpc_active_list(con); /* tcp_buf is the next buffer after tail... */
    u32_t             actual_completed_bytes = completed_bytes;
    u8_t              dbg_no_more_bufs       = FALSE;

    UNREFERENCED_PARAMETER_(tcp);

    DbgMessage(pdev, VERBOSEl4fp, "#lm_tcp_complete_bufs\n");

    /* we now have completed_bytes on RQ ( could be a result of copying from GRQ (in case of rx) or a regular rq-completion */
    con->dpc_info.dpc_rq_placed_bytes += completed_bytes;

    DbgBreakIf((con->type == TCP_CON_TYPE_RX) && !tcp_buf); /* RX: even if completed_bytes==0 */
                                                             /* Tx: tcp_buf can be NULL since this can be a fin completion
                                                             */

    while(tcp_buf && tcp_buf->more_to_comp <= completed_bytes) { /* buffer fully completed */
        DbgBreakIf((tcp_buf->more_to_comp == tcp_buf->size) &&
                   !(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_START ?
                     con->app_buf_bytes_acc_comp == 0 :
                     con->app_buf_bytes_acc_comp > 0));        

        completed_bytes -= tcp_buf->more_to_comp;            
        con->app_buf_bytes_acc_comp += tcp_buf->more_to_comp;
        tcp_buf->more_to_comp = 0; /* essential */

        /* complete buffer */
        con->dpc_info.dpc_completed_tail = &tcp_buf->link; /* last tcp_buf that needs to be completed */
        con->dpc_info.dpc_bd_used += tcp_buf->bd_used;
        con->dpc_info.dpc_bufs_completed += 1;
        con->dpc_info.dpc_actual_bytes_completed += tcp_buf->size;

        if(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END) {
            tcp_buf->app_buf_xferred = con->app_buf_bytes_acc_comp;
            DbgBreakIf(tcp_buf->app_buf_xferred != tcp_buf->app_buf_size); /* this is NOT partial completion */
            con->app_buf_bytes_acc_comp = 0;
        } else {
            if (tcp_buf->flags & TCP_BUF_FLAG_L4_SPLIT) {
                /* we've completed a split buffer */
                DbgBreakIf(GET_FLAGS(con->flags, TCP_POST_DELAYED) == 0);
                con->dpc_info.dpc_unblock_post = TRUE;
                RESET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_SPLIT);
                dbg_no_more_bufs = TRUE; /* we don't expect any more buffers after this one... */
            }
            tcp_buf->app_buf_xferred = 0;
        }

        tcp_buf = (lm_tcp_buffer_t *)s_list_next_entry(&tcp_buf->link);
        DbgBreakIf((con->type == TCP_CON_TYPE_RX) && completed_bytes && !tcp_buf);
        DbgBreakIf((con->type == TCP_CON_TYPE_TX) && completed_bytes > 1 && !tcp_buf); /* could be 1 if fin */
        DbgBreakIf(tcp_buf && dbg_no_more_bufs);
    }

    if(tcp_buf) { /* possibly, partialy completed buffer */
        DbgBreakIf((tcp_buf->more_to_comp == tcp_buf->size) &&
                   !(tcp_buf->flags & TCP_BUF_FLAG_L4_POST_START ?
                     con->app_buf_bytes_acc_comp == 0 :
                     con->app_buf_bytes_acc_comp > 0));        
        tcp_buf->more_to_comp -= completed_bytes;
        con->app_buf_bytes_acc_comp += completed_bytes;
        completed_bytes = 0;
        /* special care if push==1 AND some bytes were really completed for this buf  */
        if(push && ((tcp_buf->flags & TCP_BUF_FLAG_L4_PARTIAL_FILLED) || (con->app_buf_bytes_acc_comp > 0)) ) { 
            DbgBreakIf(con->type != TCP_CON_TYPE_RX); /* push is relevant for Rx con only */
            DbgBreakIf((push == 1) && (tcp_buf->flags & TCP_BUF_FLAG_L4_RX_NO_PUSH));

            /* skip TBs untill end of app buff - note, it's possible we don't have an end buff in case of 
             * large split buffers, in this case we'll hit the tcp buffer with the "reserved" flag, we then
             * need to mark the connection as being in the middle of completing a split buffer - meaning every
             * new buffer that will arrive will be immediately completed until the one with 'end' arrives... 
             * terrible -but there is no elegant way to deal with large split buffers... */
            do {
                tcp_buf = lm_tcp_next_entry_dpc_active_list(con);
                DbgBreakIf(!tcp_buf); /* push only comes from FW. Therefore:
					 - we can't reach this place from a peninsula to rq copy completion
					 - Since we do not post partial app bufs to the FW, if we get here
					   it is only after the entire app buff is attached to the bd chain */
                actual_completed_bytes += tcp_buf->more_to_comp;
                con->bytes_push_skip_cnt += tcp_buf->more_to_comp; /* how many bytes did we skip? */
                tcp_buf->more_to_comp = 0;
                con->partially_completed_buf_cnt++;
                /* complete buffer */
                con->dpc_info.dpc_completed_tail = &tcp_buf->link; 
                con->dpc_info.dpc_bd_used += tcp_buf->bd_used;
                con->dpc_info.dpc_bufs_completed += 1;
                con->dpc_info.dpc_actual_bytes_completed += tcp_buf->size;
            } while ( !(GET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_POST_END)) && !(GET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_SPLIT)) );

            if (GET_FLAGS(tcp_buf->flags, TCP_BUF_FLAG_L4_SPLIT)) {
                /* we've completed a split buffer */
                DbgBreakIf(GET_FLAGS(con->flags, TCP_POST_DELAYED) == 0);
                /* mark connection as "complete  next split buffers" , in the meantime this connection is delayed, so post won't look
                 * at this flag it's safe to change it lockless */
                SET_FLAGS(con->flags, TCP_POST_COMPLETE_SPLIT);
                con->dpc_info.dpc_unblock_post = TRUE;
                RESET_FLAGS(tcp_buf->flags ,TCP_BUF_FLAG_L4_SPLIT); /* this is everest internal, don't want miniport looking at this... */
            } else {
                tcp_buf->app_buf_xferred = con->app_buf_bytes_acc_comp;
                DbgBreakIf(tcp_buf->app_buf_xferred >= tcp_buf->app_buf_size); /* this is partial completion */
                con->app_buf_bytes_acc_comp = 0;             
            }
        } 
    }    
    
    /* if all bytes were completed, completed_bytes should be zero. The only case that it won't be zero is if  
     * one of the completion bytes was a 'fin' completion (TX only). In this case, completed_bytes will be '1'
     * In Rx Case, completed_bytes must always be zero. */
    DbgBreakIf((con->type == TCP_CON_TYPE_RX) && (completed_bytes != 0)); 
    DbgBreakIf((con->type == TCP_CON_TYPE_TX) && (completed_bytes > 1)); 
    return actual_completed_bytes - completed_bytes;
} /* lm_tcp_complete_nbytes */


void lm_tcp_abort_bufs(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t      * tcp,
    lm_tcp_con_t    * con, 
    lm_status_t       stat
    )
{
    lm_tcp_buffer_t * tcp_buf;
    s_list_entry_t  * lentry_p;
    s_list_t tmp_list;


    DbgBreakIf( ! (pdev && con) );
    DbgMessage(pdev, INFORMl4,
                "#lm_tcp_abort_bufs: tcp=%p, con type=%d, stat=%d\n",
                tcp, con->type, stat);

    s_list_init(&tmp_list, NULL, NULL, 0);

	/* we don't expect there to be any pending completions... (unless we're in error recovery) */
    if (!lm_reset_is_inprogress(pdev))
    {
    DbgBreakIf ((con->type == TCP_CON_TYPE_RX) && (con->u.rx.skp_bytes_copied));
    }


    /* If there is completed data, report it in the first seen END-buffer.
       There must be at most one not completed App. Buf.   
     */
    lentry_p = s_list_pop_head(&con->active_tb_list);
    while( lentry_p)  {

        tcp_buf = (lm_tcp_buffer_t *)lentry_p;
        con->rq_nbytes -= tcp_buf->size;

        tcp_buf->app_buf_xferred = 0;

        /* Take care of partially completed buffer */
        if (tcp_buf->flags & TCP_BUF_FLAG_L4_POST_END) {
            tcp_buf->app_buf_xferred = con->app_buf_bytes_acc_comp;
            DbgBreakIf(tcp_buf->app_buf_size < con->app_buf_bytes_acc_comp);
            con->app_buf_bytes_acc_comp = 0; 
            DbgBreakIf(S32_SUB(S64_SUB(con->bytes_post_cnt, con->bytes_comp_cnt), (tcp_buf->app_buf_size - tcp_buf->app_buf_xferred)) < 0);
            con->bytes_comp_cnt += (tcp_buf->app_buf_size - tcp_buf->app_buf_xferred);
            con->bytes_aborted_cnt += (tcp_buf->app_buf_size - tcp_buf->app_buf_xferred);
        } 
        
        s_list_push_tail(&tmp_list, &tcp_buf->link);

        lentry_p = s_list_pop_head(&con->active_tb_list);
    }

    /* GilR 8/3/2006 - TODO - can't assert here. pending might be 1 if fin request was posted and not completed (tx con) */
    //DbgBreakIf(con->pending_bytes);

    /* Complete all buffers from active_list */
    if(s_list_entry_cnt(&tmp_list)) {
        con->buffer_aborted_cnt += s_list_entry_cnt(&tmp_list);
        if (lm_fl_reset_is_inprogress(pdev)) {
            con->abortion_under_flr++;
        }
	mm_tcp_complete_bufs(pdev, tcp, con, &tmp_list, stat);
    }    
    con->flags |= TCP_BUFFERS_ABORTED;

    /* Abort all pending buffers in UM */
    mm_tcp_abort_bufs(pdev,tcp,con,stat);

    DbgBreakIf(!s_list_is_empty(&con->active_tb_list));
}

/******** qe_buffer interface: cyclic NON-OVERRIDE buffer  ****************/

/** Description
 *  returns the next cqe in the cqe_buffer and updates the buffer params
 */ 
char * lm_tcp_qe_buffer_next_free_cqe(lm_tcp_qe_buffer_t * cqe_buffer)
{
    char * cqe;

    cqe = cqe_buffer->head;

    if(cqe == cqe_buffer->last) {
        cqe_buffer->head = cqe_buffer->first; /* cyclic*/
    } else {
        cqe_buffer->head = cqe + cqe_buffer->qe_size;
    }

    DbgBreakIf(cqe_buffer->left == 0);
    cqe_buffer->left--;

    return cqe;
}

/** Description
 *  returns the next occupied cqe in the cqe_buffer and updates the buffer params
 * (tail)
 */ 
char * lm_tcp_qe_buffer_next_occupied_cqe(lm_tcp_qe_buffer_t * cqe_buffer)
{
    char * cqe;

    cqe = cqe_buffer->tail;

    if ((cqe == cqe_buffer->head) && (cqe_buffer->left > 0)) {
        return NULL;
    }

    if(cqe == cqe_buffer->last) {
        cqe_buffer->tail = cqe_buffer->first; /* cyclic*/
    } else {
        cqe_buffer->tail = cqe + cqe_buffer->qe_size;
    }
    
    cqe_buffer->left++;

    return cqe;
}

u8_t lm_tcp_qe_buffer_is_empty(lm_tcp_qe_buffer_t * cqe_buffer)
{
    return ((cqe_buffer->head == cqe_buffer->tail) && (cqe_buffer->left > 0));
}

/******** qe_buffer interface: cyclic OVERRIDE buffer  ****************/
char * lm_tcp_qe_buffer_next_cqe_override(lm_tcp_qe_buffer_t * cqe_buffer)
{
    char * cqe;

    cqe = cqe_buffer->head;

    if(cqe == cqe_buffer->last) {
        cqe_buffer->head = cqe_buffer->first; /* cyclic*/
    } else {
        cqe_buffer->head = cqe + cqe_buffer->qe_size;
    }

    if (cqe_buffer->left) {
        cqe_buffer->left--;
    }
    
    return cqe;
}




