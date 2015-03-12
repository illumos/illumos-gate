/*******************************************************************************
 * lm_l4st.h - L4 lm data structures 
 ******************************************************************************/
#ifndef _LM_L4ST_H
#define _LM_L4ST_H

#include "l4states.h"
#include "bd_chain_st.h"
#include "lm_sp_req_mgr.h"
#include "toe_constants.h"

#define MAX_L4_RX_CHAIN                16
#define MAX_L4_TX_CHAIN                16

#define PATTERN_COUNTER_IDX_COMPLETION   0
#define PATTERN_COUNTER_IDX_CQE         1
#define MAX_PATTERN_IDX                 2

typedef struct _lm_tcp_integrity_info_t
{
    u32_t current_offset_in_pattern_buf[MAX_PATTERN_IDX];
    u32_t skip_bytes_in_incoming_buf[MAX_PATTERN_IDX];
    u32_t  is_offsets_initialized;
} lm_tcp_integrity_info_t;


typedef struct _lm_toe_integrity_info_t
{
    u8_t  *  pattern_buf;
    u32_t   pattern_buf_size;
    u32_t   pattern_size;
} lm_toe_integrity_info_t;


/*******************************************************************************
 * 'Posting' TCP buffer. 
 ******************************************************************************/
typedef struct _lm_tcp_buffer_t
{
    /* Must be the first entry in this structure. */
    s_list_entry_t      link;

    /* Corresponds to l4buffer_t buffer_size.
     * The number of bytes in this buffer may not corresponds to the 
     * the number of bytes of the application buffer.  An application buffer
     * could span multiple tcp_bufs.  The flags field is used to mark the
     * starting and the end of an application buffer. */
    u32_t               size;

    /* Number of bytes that were not completed yet */
    u32_t               more_to_comp;
    
    u32_t                flags;      /* Flags for indicating the start and end of an io buffer. */
    #define TCP_BUF_FLAG_NONE                   0x00
    #define TCP_BUF_FLAG_L4_POST_START          0x01
    #define TCP_BUF_FLAG_L4_POST_END            0x02
    #define TCP_BUF_FLAG_L4_RESERVED1           0x04  /* used in Teton for dummy buffer. */
    #define TCP_BUF_FLAG_L4_SPLIT               0x04  /* Used in everest for split buffer Everest cleans before completing to miniport */
    #define TCP_BUF_FLAG_L4_RESERVED2           0x08  /* used only in Miniport as 'last post' */
    #define TCP_BUF_FLAG_L4_RX_NO_PUSH          0x10  
    #define TCP_BUF_FLAG_L4_PARTIAL_FILLED      0x20
    /* NOTE: lm_tcp_buffer flags values must correspond to flags definition in l4buffer_t */

    u16_t               bd_used;    /* Number of BDs consumed in the bd chain for this tcp buffer */
    u16_t               _pad;
    
    /* These fields are valid when TCP_BUF_FLAG_L4_POST_END flag is set. */
    u32_t app_buf_size;     /* Number of bytes of all buffers from BUFFER_START till BUFFER_END */
    u32_t app_buf_xferred;  /* Number of bytes xferred on all buffers from BUFFER_START till BUFFER_END */
} lm_tcp_buffer_t;

/*******************************************************************************
 * state header. 
 * Each state must start with this entry, which is used for chaining 
 * states together and for identifying a particular state. 
 ******************************************************************************/
typedef struct _lm_state_header_t
{
    d_list_entry_t link;
    struct _lm_state_block_t *state_blk;

    u32_t state_id;
    #define STATE_ID_UNKNOWN                    0
    #define STATE_ID_TCP                        1
    #define STATE_ID_PATH                       2
    #define STATE_ID_NEIGH                      3

    u32_t status;
    #define STATE_STATUS_UNKNOWN                0
    #define STATE_STATUS_INIT                   1
    #define STATE_STATUS_INIT_CONTEXT           2
    #define STATE_STATUS_OFFLOAD_PENDING        3
    #define STATE_STATUS_NORMAL                 4
    #define STATE_STATUS_ABORTED                5
    #define STATE_STATUS_INVALIDATED            6
    #define STATE_STATUS_UPLOAD_PENDING         7
    #define STATE_STATUS_UPLOAD_DONE            8
    #define STATE_STATUS_INIT_OFFLOAD_ERR       9
    #define STATE_STATUS_ERR                    10
} lm_state_header_t;

/*******************************************************************************
 * neighbor state
 ******************************************************************************/
typedef struct _lm_neigh_state_t
{
    lm_state_header_t           hdr;

    l4_neigh_const_state_t      neigh_const;
    l4_neigh_cached_state_t     neigh_cached;
    l4_neigh_delegated_state_t  neigh_delegated;

    /* network reachability */
    u32_t                       host_reachability_time;
    u32_t                       nic_reachability_time;
    u8_t                        stale;
    u8_t                        _pad[3];

    /* debug */
    u32_t                       num_dependents; /* number of dependent path states */
} lm_neigh_state_t;

/*******************************************************************************
 * path state
 ******************************************************************************/
typedef struct _lm_path_state_t
{
    lm_state_header_t           hdr;

    lm_neigh_state_t            *neigh;         /* parent neighbor state */

    l4_path_const_state_t       path_const;
    l4_path_cached_state_t      path_cached;
    l4_path_delegated_state_t   path_delegated;

    /* debug */
    u32_t                       num_dependents; /* number of dependent tcp states */
} lm_path_state_t;

/*******************************************************************************
 * queue element buffer - for buffering queue elements (of any type)
 ******************************************************************************/
typedef struct _lm_tcp_qe_buffer_t
{
    char *first;
    char *tail;
    char *head;
    char *last;

    u32_t qe_size; /* queue element size */
    u32_t left;
} lm_tcp_qe_buffer_t;


/*******************************************************************************
 * Memory Blocks
 ******************************************************************************/
typedef struct _lm_tcp_mem_block_t
{
    s_list_entry_t   link;  /* Must be the first entry... */

    u8_t           * start; /* Start of the memory block */
    u8_t           * free;  /* Pointer to the start of the remaining free space of the block */
    u32_t            total; /* Size of the entire block */
    u32_t            left;  /* free bytes left in the block */
    u8_t             flags;  /* virt-memblock-pool member or not */        
    #define MBLK_RETURN_TO_POOL 0x1
} lm_tcp_mem_block_t;

typedef struct _lm_tcp_phy_mem_block_t
{
    s_list_entry_t   link;

    u8_t           * start; /* Start of the memory block */
    u8_t           * free;  /* Pointer to the start of the remaining free space of the block */
    u32_t            total; /* Size of the entire block */
    u32_t            left;  /* free bytes left in the block */ 

    lm_address_t     start_phy;
    lm_address_t     free_phy;
} lm_tcp_phy_mem_block_t;

#define DEBUG_OOO_CQE
typedef struct _lm_isle_t
{
    d_list_entry_t   isle_link;
    d_list_t         isle_gen_bufs_list_head;
    u32_t            isle_nbytes;
#ifdef DEBUG_OOO_CQE
    u32_t            dedicated_cid;
    u32_t            recent_ooo_combined_cqe;
#endif
} lm_isle_t;

#ifdef DEBUG_OOO_CQE
#define SET_DEBUG_OOO_INFO(_isle, _cmd, _data) \
             (_isle)->recent_ooo_combined_cqe = ((((_cmd) << TOE_RX_CQE_COMPLETION_OPCODE_SHIFT) & TOE_RX_CQE_COMPLETION_OPCODE) \
                                                | (((_data) << TOE_RX_CQE_OOO_PARAMS_NBYTES_SHIFT) & TOE_RX_CQE_OOO_PARAMS_NBYTES))
#define GET_RECENT_OOO_CMD(_isle) \
             (((_isle)->recent_ooo_combined_cqe &  TOE_RX_CQE_COMPLETION_OPCODE) >>  TOE_RX_CQE_COMPLETION_OPCODE_SHIFT)
#define GET_RECENT_OOO_DATA(_isle) \
             (((_isle)->recent_ooo_combined_cqe &  TOE_RX_CQE_OOO_PARAMS_NBYTES) >>  TOE_RX_CQE_OOO_PARAMS_NBYTES_SHIFT)
#endif

/*******************************************************************************
 * Rx connection's generic buffers info. 
 ******************************************************************************/
typedef struct _lm_tcp_con_rx_gen_info_t
{
    d_list_t         peninsula_list;     /* accessed only via lock */
    d_list_t         dpc_peninsula_list; /* accessed lock-free only in dpc */

    d_list_t         isles_list;
    lm_isle_t        first_isle;
    lm_isle_t      * current_isle;
    u8_t             current_isle_number;
    u8_t             max_number_of_isles;
    u8_t             _isle_pad[2];

    lm_frag_list_t * frag_list;         /* allocated in initialization of connection      */
    u32_t            max_frag_count;    /* the number of frags statically allocated       */

    u32_t            peninsula_nbytes;
    u32_t            dpc_peninsula_nbytes;
    u32_t            isle_nbytes;
    u16_t            first_buf_offset;

    /* How many buffers (head of indications) were indicated for this connection and haven't 
     * returned yet from NDIS. We need to know that to make sure we don't delete the connection 
     * before all buffers pointing to it have returned. 
     */
    u16_t            pending_return_indications;
    /* bytes indicated that their buffers have not yet been returned, this is a value that will increase
     * the window. If we're uploaded and we still have pending_indicated_bytes we need to increase them immediataly
     * and not wait... */
    u32_t            pending_indicated_bytes; 

    /* Each indication may result in us updating the window - this depends on the #of bytes accepted AND the update_window_mode
     * we're in. We aggregate this over all indications (mm_tcp_rx_indicate_gen may be called several times if more generic data
     * was received during indicate). This field is updated ONLY by the function lm_tcp_rx_buffered_data_indicated, and is accessed
     * once the mm_tcp_rx_indicate_gen function completes. The main reason for this aggregation, unfortunatelly, is for passing 
     * SpartaTest - receive_indications, which expects a specific number of indications.  */
    u32_t            add_sws_bytes;

    u8_t             wait_for_isle_left;
    u8_t            _padding;

    /* The update window mode is taken from the toe information before an indication
     * We can't use the main copy because it may change between the time we indicate 
     * (after we've marked the buffer) and the time we get an answer (and need to determine 
     * whether to update the window or not) */
    u8_t             update_window_mode;    

    /*  debug/statistics */
    /* DEFINITION: A generic buffer can be 'done' with as a result of a succesfull indicate or as a result of a copy
     * operation to an application buffer. (regardless of its state before: partially indicated/partially copied). 
     * We count the number of times generic buffers were 'done' with */
    u8_t             peninsula_blocked;     /* peninsula is blocked as a result of terminate (get_buffered_data) */ 
    u32_t            num_buffers_indicated; /* 'done' with as a result of an indicate */
    u32_t            num_buffers_copied_grq;/* # grq buffers copied */
    u32_t            num_buffers_copied_rq; /* # rq buffers copied TBD how to count*/
    u32_t            num_bytes_indicated;   /* all bytes indicated in either full/partial indications */
    u32_t            copy_gen_buf_fail_cnt; /* counts the number of times a client.copy operation failed */
    u32_t            copy_gen_buf_dmae_cnt; /* counts the number of times dmae copy operation was used */
    u32_t            num_success_indicates; /* number of times indicate succeeded */
    u32_t            num_failed_indicates;  /* number of times indicate failed */
    u32_t            bufs_indicated_rejected; /* number of rejected bufs */
    u64_t            bytes_copied_cnt_in_process;
    u64_t            bytes_copied_cnt_in_post;
    u64_t            bytes_copied_cnt_in_comp;
    u64_t            bytes_indicated_accepted;
    u64_t            bytes_indicated_rejected;
    u32_t            dont_send_to_system_more_then_rwin;
    u32_t            num_non_full_indications;

} lm_tcp_con_rx_gen_info_t;

/*******************************************************************************
 * Rx connection's receive window information for silly window syndrome avoidance
 ******************************************************************************/
#define MAX_INITIAL_RCV_WND 0x80000000 /* 2GB (due to cyclic counters and window-update algorithm */

/* DWA: Delayed Window Update Algorithm : the twin of DCA, delay the window updates according to the delayed completions. */

#define MAX_DW_THRESH_ENTRY_CNT 16 /* a new entry is created each time we see a NDC completion (non-delayed-complete). We
                                    * can limit these to 16 'active completions' i.e. completions that haven't received a 
                                    * window-update yet. FW-DCA works with quad-buffer, therefore 16 is more than enough. */

typedef struct _lm_tcp_rx_dwa_info {
    u32_t dw_thresh[MAX_DW_THRESH_ENTRY_CNT]; /* delayed window update thresholds. */
    u8_t  head;                               /* head of the the cyclic buffer dw_thresh (next empty entry) */
    u8_t  tail;                               /* tail of the the cyclic buffer dw_thresh */
    u16_t _pad;
} lm_tcp_rx_dwa_info;

typedef struct _lm_tcp_con_rx_sws_info_t
{
    u32_t  drv_rcv_win_right_edge; /* The drivers window right edge (shadow of fw, and may be 
                                    * larger if the difference is smaller than mss) */
    u32_t  mss;                     /* min(tcp_const.remote_mss, 
                                      parent_path->path_cached.path_mtu - HEADERS size) */
    u32_t extra_bytes;

    u8_t   timer_on;
} lm_tcp_con_rx_sws_info_t;

/*******************************************************************************
 * Rx connection's special information
 ******************************************************************************/
typedef struct _lm_tcp_con_rx_t
{
    lm_tcp_con_rx_gen_info_t    gen_info;
    lm_tcp_con_rx_sws_info_t    sws_info;

    /* Last bd written to: required in spcecial case of very large application buffers
     * not fitting into the bd-chain . */
    struct toe_rx_bd * last_rx_bd;

    /* Remember a remote disconnect event until all received data is
     * completed/indicated successfully to the client */
    u8_t                        flags;
    #define TCP_CON_RST_IND_PENDING             0x1
    #define TCP_CON_FIN_IND_PENDING             0x2
    u8_t                        zero_byte_posted_during_ind;
    u8_t                        check_data_integrity_on_complete;
    u8_t                        check_data_integrity_on_receive;
    u32_t                       compared_bytes;

    u32_t skp_bytes_copied; /* counter of bytes that were already copied to the buffer at post that we 
                             * will receive a skip for which we'll need to ignore...This counter must be protected
                             * by a lock */
    /* GilR 4/3/2006 - TBA - add lm tcp con rx debug/stats fields? */        
    u32_t rx_zero_byte_recv_reqs; /* #Zero byte receeive requests */
} lm_tcp_con_rx_t;

/*******************************************************************************
 * Tx connection's special information
 ******************************************************************************/
typedef struct _lm_tcp_con_tx_t
{
    u16_t   bds_without_comp_flag; /* counter of consecutive BDs without CompFlag */
    u8_t   flags;
    #define TCP_CON_FIN_REQ_LM_INTERNAL     0x1 /* FIN request completion should
                                         * not be indicated to mm */
    #define TCP_CON_RST_IND_NOT_SAFE 0x2
    

    u8_t   _pad;
    u32_t mss;
} lm_tcp_con_tx_t;


/*******************************************************************************
 * TCP connection - rx OR tx
 ******************************************************************************/
/* This structure is used to collect information during a DPC without taking the
 * fp-lock. All fields in this structure must be accessed ONLY from within the 
 * the DPC 
 */
typedef struct _lm_tcp_dpc_info_t
{
    s_list_entry_t    link; /* must be the first entry here */
    s_list_entry_t  * dpc_completed_tail; /* points to the tail of the sub-list of active_tb_list that needs to
                                           * be completed. */
    u32_t             dpc_bufs_completed; /* number of buffers completed in the dpc (aggregated during process
                                           * stage for fast splitting of the active_tb_list at completion stage)*/
    u32_t             dpc_rq_placed_bytes; /* how many bytes were placed on rq as a result of rq-cmp / copying from grq->rq */
    u32_t             dpc_actual_bytes_completed; /* number of bytes completed to client - aggregated during process stage */
    u16_t             dpc_bd_used;        /* number of bds used - aggregated during process stage */
    u16_t             dpc_flags;          /* flags marked during cqe processing - only accessed during processing and
                                           * snapshot-ed under a lock */
    #define LM_TCP_DPC_RESET_RECV 0x1  
    #define LM_TCP_DPC_FIN_RECV   0x2
    #define LM_TCP_DPC_FIN_CMP    0x4
    #define LM_TCP_DPC_KA_TO      0x8
    #define LM_TCP_DPC_RT_TO      0x10
    #define LM_TCP_DPC_URG        0x20
    #define LM_TCP_DPC_RAMROD_CMP 0x40
//    #define LM_TCP_DPC_NDC        0x80
    #define LM_TCP_DPC_DBT_RE     0x100
    #define LM_TCP_DPC_OPT_ERR    0x200
    #define LM_TCP_DPC_UPLD_CLOSE 0x400
    #define LM_TCP_DPC_FIN_RECV_UPL 0x800
    #define LM_TCP_DPC_TOO_BIG_ISLE     0x1000
    #define LM_TCP_DPC_TOO_MANY_ISLES   0x2000

/*
    #define LM_TCP_COMPLETE_FP (LM_TCP_DPC_RESET_RECV | LM_TCP_DPC_FIN_RECV | LM_TCP_DPC_FIN_RECV_UPL | LM_TCP_DPC_FIN_CMP | \
                                LM_TCP_DPC_KA_TO | LM_TCP_DPC_RT_TO | LM_TCP_DPC_URG | LM_TCP_DPC_RAMROD_CMP | LM_TCP_DPC_NDC | \
                                LM_TCP_DPC_DBT_RE | LM_TCP_DPC_OPT_ERR | LM_TCP_DPC_UPLD_CLOSE | \
                                LM_TCP_DPC_TOO_BIG_ISLE | LM_TCP_DPC_TOO_MANY_ISLES)
*/
    /* dpc snapshot parameters: taken before an operation that can release a lock is done 
     * in lm_tcp_xx_complete_fp */
    u16_t              snapshot_flags; /* only accessed under lock */

    /* we have special cases where lm blocks um from posting until a specific buffer gets completed, we have a flag for this
     * this flag is accessed with the post flow, so it should be protected by a lock, therefore we remember we have to unset it
     * in the completion stage (under a lock) */
    u8_t               dpc_unblock_post;
    /* debug / stats */
    u8_t              dpc_comp_blocked;

    /* the window size returned from the fw after window size decreasment request returned, written back to the fw */
    u32_t             dpc_fw_wnd_after_dec;
    
} lm_tcp_dpc_info_t;

typedef struct _lm_tcp_con_t
{
    lm_tcp_dpc_info_t dpc_info; /* must be the first field */

    struct _lm_tcp_state_t * tcp_state; /* The tcp state associated with this connection */

    union {
        volatile struct toe_rx_db_data  *rx; 
        volatile struct toe_tx_db_data  *tx; 
    } db_data;
    lm_address_t        phys_db_data;    

    /* rx/tx tcp connection info. */
    union
    {
        lm_tcp_con_rx_t rx;
        lm_tcp_con_tx_t tx;
    } u;

    lm_bd_chain_t bd_chain;
    
    /* List of posted buffers (i.e. attached to the bd chain) */
    s_list_t        active_tb_list;
    u32_t           rq_nbytes; /* how many bytes are in the active-tb-list */

    /* buffer of cqes that represent the last X cqes received */
    lm_tcp_qe_buffer_t history_cqes;

    u32_t           type;
    #define TCP_CON_TYPE_RX                     1
    #define TCP_CON_TYPE_TX                     2

    /* accumulator of currently posted application buffer bytes. 
     * accumulated in order to set lm_tcp_buffer.app_buf_size of 
     * the last tcp buffer of the application buffer */
    u32_t           app_buf_bytes_acc_post;

    /* accumulator of currently completed application buffer bytes.
     * accumulated in order to set lm_tcp_buffer.app_buf_xferred of 
     * the last tcp buffer of the application buffer */
    u32_t           app_buf_bytes_acc_comp;

    u32_t           db_more_bytes;  /* number of bytes to be produced in next doorbell */    
    u16_t           db_more_bufs;   /* number of tcp buffers to be produced in next doorbell */
    u16_t           db_more_bds;    /* number of bds to be produced in next doorbell */
    
    /* flags are used for managing the connection's posting/completing/indicating state machines */
    u32_t           flags;
    #define TCP_FIN_REQ_POSTED                              0x0001
    #define TCP_RST_REQ_POSTED                              0x0002
    #define TCP_INV_REQ_POSTED                              0x0004
    #define TCP_TRM_REQ_POSTED                              0x0008
    #define TCP_FIN_REQ_COMPLETED                           0x0010
    #define TCP_RST_REQ_COMPLETED                           0x0020
    #define TCP_INV_REQ_COMPLETED                           0x0040
    #define TCP_TRM_REQ_COMPLETED                           0x0080
    #define TCP_REMOTE_FIN_RECEIVED                         0x0100
    #define TCP_REMOTE_RST_RECEIVED                         0x0200
    #define TCP_REMOTE_FIN_RECEIVED_ALL_RX_INDICATED        0x0400
    #define TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED        0x0800
    #define TCP_INDICATE_REJECTED                           0x1000
    #define TCP_POST_BLOCKED                                0x2000
    #define TCP_COMP_BLOCKED                                0x4000
    #define TCP_COMP_DEFERRED                               0x8000
    #define TCP_BUFFERS_ABORTED                            0x10000
    #define TCP_DEFERRED_PROCESSING                        0x20000 
    #define TCP_POST_DELAYED                               0x40000 /* lm sets this when posting buffers is delay for some reason */
    #define TCP_POST_COMPLETE_SPLIT                        0x80000 /* lm sets this when every split  buffer that'll be posted will be completed immediately */
    #define TCP_POST_NO_SKP                               0x100000 /* lm sets this when there will  be no more skp completions from fw (comp blocked...)  */
    #define TCP_UPLOAD_REQUESTED                          0x200000 /* lm sets this when FW requests an upload for any reason - after this is set, no more uploads will be requested*/
    #define TCP_DB_BLOCKED                                0x400000
    #define TCP_RX_DB_BLOCKED       (TCP_REMOTE_FIN_RECEIVED | TCP_REMOTE_RST_RECEIVED | TCP_DB_BLOCKED)
    #define TCP_TX_DB_BLOCKED       (TCP_REMOTE_RST_RECEIVED | TCP_DB_BLOCKED)
    #define TCP_TX_POST_BLOCKED     (TCP_FIN_REQ_POSTED | TCP_RST_REQ_POSTED | TCP_INV_REQ_POSTED | TCP_TRM_REQ_POSTED | \
                                     TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED | TCP_POST_BLOCKED \
                                     )
                                    /* GilR 4/4/2006 - TBD - open issue with Hav, for Tx POST BLOCKED we might not wait for 'rx indicated' after RST received */
    #define TCP_RX_POST_BLOCKED     (TCP_RST_REQ_POSTED | TCP_INV_REQ_POSTED | TCP_TRM_REQ_POSTED | \
                                     TCP_REMOTE_RST_RECEIVED_ALL_RX_INDICATED | TCP_REMOTE_FIN_RECEIVED_ALL_RX_INDICATED | \
                                     TCP_POST_BLOCKED)
    #define TCP_TX_COMP_BLOCKED     (TCP_RST_REQ_COMPLETED | TCP_FIN_REQ_COMPLETED | TCP_REMOTE_RST_RECEIVED | \
                                     TCP_INV_REQ_COMPLETED | TCP_TRM_REQ_COMPLETED | TCP_COMP_BLOCKED \
                                     )
    #define TCP_RX_COMP_BLOCKED     (TCP_RST_REQ_COMPLETED | TCP_REMOTE_FIN_RECEIVED | TCP_REMOTE_RST_RECEIVED | \
                                     TCP_INV_REQ_COMPLETED | TCP_TRM_REQ_COMPLETED | TCP_COMP_BLOCKED \
                                     )
    #define TCP_TX_COMP_DEFERRED     TCP_COMP_DEFERRED
    #define TCP_RX_COMP_DEFERRED     TCP_COMP_DEFERRED
    #define TCP_RX_IND_BLOCKED      (TCP_RST_REQ_POSTED | TCP_INV_REQ_POSTED | TCP_TRM_REQ_POSTED | TCP_INDICATE_REJECTED)
    
    /* GilR 4/3/2006 - TBA - add lm con debug/statistics */
    u64_t bytes_post_cnt;       /* cyclic counter of posted application buffer bytes */
    u64_t bytes_comp_cnt;       /* cyclic counter of completed application buffer bytes (including skipped bytes due to push) */    
    u64_t bytes_push_skip_cnt;
    u64_t bytes_skip_post_cnt;  /* skipped post because of generic data */
    u32_t buffer_skip_post_cnt; /* skipped post because of generic data */
    u32_t buffer_post_cnt;
    u32_t buffer_completed_cnt;
    u32_t rq_completion_calls;
    u32_t partially_completed_buf_cnt; /* included in 'buffer_completed_cnt' above */
    u32_t buffer_aborted_cnt;
    u64_t bytes_aborted_cnt;       /* cyclic counter of aborted application buffer bytes */    
    u32_t bytes_trm_aborted_cnt;   /* cyclic counter of bytes received with rst ramrod completion */    
    u32_t fp_db_cnt;   /* Fast path doorbell counter - doens't count Adv. Wnd. doorbells*/
    u32_t indicate_once_more_cnt;
    u32_t droped_non_empty_isles;
    u32_t droped_empty_isles;
    u32_t rx_post_blocked;
    u32_t zb_rx_post_blocked;
    u32_t partially_filled_buf_sent;
    u32_t abortion_under_flr;
} lm_tcp_con_t;


/*******************************************************************************
 * Slow path request information  
 ******************************************************************************/
/* structure used for storing the data returned by a completion of a slow-path request */
typedef union _lm_tcp_slow_path_ret_data_t
{
    struct {
        lm_frag_list_t            * frag_list;
        struct _lm_tcp_gen_buf_t  * ret_buf_ctx;
    } tcp_upload_data;
} lm_tcp_slow_path_ret_data_t;

/* structure used for storing the data required for a slow-path request */
typedef struct _lm_tcp_path_relink_cached_t
{
    l4_path_cached_state_t  path_cached;
    l4_neigh_cached_state_t neigh_cached;
} lm_tcp_path_relink_cached_t;

typedef union _lm_tcp_slow_path_sent_data_t {
    struct {
        void * data;
    } tcp_update_data;
} lm_tcp_slow_path_sent_data_t ;

typedef union _lm_tcp_slow_path_phys_data_t
{
    struct toe_context toe_ctx; /* used by query slow path request */
    struct toe_update_ramrod_cached_params update_ctx; /* used by update slow path request */

} lm_tcp_slow_path_phys_data_t;

typedef struct _lm_tcp_slow_path_data_t {
    lm_tcp_slow_path_phys_data_t  * virt_addr;
    lm_address_t                    phys_addr;    
}lm_tcp_slow_path_data_t ;

typedef struct _lm_tcp_slow_path_request_t
{
    lm_sp_req_common_t sp_req_common;
    lm_tcp_slow_path_ret_data_t  ret_data;    /* SP req. output data */
    lm_tcp_slow_path_sent_data_t sent_data;   /* SP req. input data  */

    u32_t    type;
    #define SP_REQUEST_NONE                         0    
    #define SP_REQUEST_INITIATE_OFFLOAD             1     
    #define SP_REQUEST_TERMINATE_OFFLOAD            2
    #define SP_REQUEST_QUERY                        3
    #define SP_REQUEST_UPDATE_TCP                   4
    #define SP_REQUEST_UPDATE_PATH                  5
    #define SP_REQUEST_UPDATE_NEIGH                 6
    #define SP_REQUEST_INVALIDATE                   7
    #define SP_REQUEST_ABORTIVE_DISCONNECT          8
    #define SP_REQUEST_TERMINATE1_OFFLOAD           9
    #define SP_REQUEST_PENDING_LOCAL_FIN_DISCONNECT 10 /* used only for LOCAL graceful disconnect */
    #define SP_REQUEST_PENDING_REMOTE_DISCONNECT    11 /* used for both abortive and graceful disconnect */
    #define SP_REQUEST_PENDING_TX_RST               12 /* used for TX Reset received while buffers in the active-tb-list */
    #define SP_REQUEST_BLOCKED                      13 /* when there is no pending connection, we just want to block sp-command
                                                        * for example, delay offload */  
    #define SP_REQUEST_UPDATE_PATH_RELINK           14
    lm_status_t status; /* request completion status */    
} lm_tcp_slow_path_request_t;

/*******************************************************************************
 * information required for calculating the TCP state on 'query' 
 * and 'terminate' completions
 ******************************************************************************/
typedef struct _lm_tcp_state_calculation_t
{
    u64_t fin_request_time;     /* written by Tx path, when a fin request is posted to the chip */
    u64_t fin_completed_time;   /* written by Tx path, when a fin request is completed by the chip */
    u64_t fin_reception_time;   /* written by Rx path, when a remote fin is received */
    u8_t  con_rst_flag;         /* set whenever chip reports RST reception or RST sent completion */
    u8_t  con_upld_close_flag;  /* set whenever chip reports request to upload a connection after SYN was received or FIN_WAIT2 timer expired */
    u8_t  _pad[2];
} lm_tcp_state_calculation_t;

/*******************************************************************************
 * tcp state
 ******************************************************************************/
typedef struct _lm_tcp_state_t
{
    lm_state_header_t           hdr;
    lm_path_state_t             *path;
    lm_tcp_con_t                *rx_con;
    lm_tcp_con_t                *tx_con;
    lm_tcp_slow_path_request_t  *sp_request;
    lm_tcp_slow_path_data_t     sp_req_data;
    lm_tcp_state_calculation_t  tcp_state_calc;
    void                        *ctx_virt; /* Can point to different structures depending on the ulp_type */
    lm_address_t                ctx_phys;
    l4_tcp_delegated_state_t    tcp_delegated;
    l4_tcp_const_state_t        tcp_const;
    l4_tcp_cached_state_t       tcp_cached;

    u32_t                       cid;
    #define TCP_CID_MASK 0xffffff

    /* synchronization between Tx and Rx completions of slow path events */
    u16_t                       sp_flags;
    #define SP_REQUEST_COMPLETED_RX     0x001
    #define SP_REQUEST_COMPLETED_TX     0x002
    #define REMOTE_RST_INDICATED_RX     0x004
    #define REMOTE_RST_INDICATED_TX     0x008
    /* mainly for debugging purposes... slow-path indications when there is no fp... */
    #define SP_TCP_OFLD_REQ_POSTED      0x010
    #define SP_TCP_SRC_REQ_POSTED       0x020
    #define SP_TCP_TRM_REQ_POSTED       0x040
    #define SP_TCP_QRY_REQ_POSTED       0x080
    #define SP_TCP_OFLD_REQ_COMP        0x100
    #define SP_TCP_SRC_REQ_COMP         0x200
    #define SP_TCP_TRM_REQ_COMP         0x400
    #define SP_TCP_QRY_REQ_COMP         0x800

    u8_t                       in_searcher;   /* was the tcp state added to searcher hash */ 
    u8_t                       ulp_type;
    void *                     aux_memory;
    u32_t                      aux_mem_size;
    u8_t                       type_of_aux_memory;
    #define TCP_CON_AUX_RT_MEM          0x1
    u8_t                       aux_mem_flag;
    #define TCP_CON_AUX_RT_MEM_SUCCSESS_ALLOCATION          0x1
    #define TCP_CON_AUX_RT_MEM_FAILED_ALLOCATION            0x2

    u8_t                       sp_request_pending_completion;
    u8_t                       pending_abortive_disconnect; 

    lm_tcp_integrity_info_t    integrity_info;
    /* GilR 4/3/2006 - TBA - add lm tcp state debug/statistics */
} lm_tcp_state_t;

/*******************************************************************************
 * Generic TCP buffer. 
 ******************************************************************************/
typedef struct _lm_tcp_gen_buf_t
{
    d_list_entry_t   link;  /* MUST be the first field in this structure */
    /* generic buffers create a list of generic buffers. The next element is infact a d_list_entry, 
     * however, the generic buffer list is not always accessed as a d_list, it is sometime traversed as
    * a list ending with NULL */
    #define NEXT_GEN_BUF(_gen_buf) (struct _lm_tcp_gen_buf_t *)d_list_next_entry(&((_gen_buf)->link))
    #define PREV_GEN_BUF(_gen_buf) (struct _lm_tcp_gen_buf_t *)d_list_prev_entry(&((_gen_buf)->link))

    lm_address_t     buf_phys;
    lm_tcp_state_t * tcp;    /* mainly for updating pending_return_indications */
    u8_t           * buf_virt;

    /* Following 4 fields are used for supporting SWS accessed when buffer is returned */
    u32_t            ind_bytes; /* set only in buffer that is head of indication - how many bytes were indicated */
    u32_t            ind_nbufs; /** how many buffers were included in the indication. Needed for:
                                 *  - returning buffers to generic pool
                                 *  - efficiently restore the peninsula list */
    /** refcnt required only if we support RcvIndicationSize > 0 */
    u16_t            refcnt; /* reference count for number of times the buffer was succesfully indicated to um */
    u16_t            placed_bytes;

    /* The FREE_WHEN_DONE flag indicates that this generic buffer
     * contains the buffered data received when doing tcp_offload and when it is completed, this
     * generic buffer is freed back into system memory instead of the generic buffer pool. */
    u8_t flags;
    #define GEN_FLAG_FREE_WHEN_DONE 0x01
    #define GEN_FLAG_SWS_UPDATE     0x02 /* In certain cases succesfull indication updates the window immediately, however
                                          * when we enter a 'safe-mode' we wait for the generic buffers to return before we 
                                          * update the window. This flag indicates whether or not we have to update. */

    u16_t phys_offset;                   /* When allocating gen bufs for buffered data, save the offset 
                                            from the original phys addr, and use it when when we free the gen buf */

} lm_tcp_gen_buf_t;


/*******************************************************************************
 * generic buffer queue
 ******************************************************************************/
typedef struct _lm_tcp_grq_t
{
    lm_bd_chain_t       bd_chain;
    
    /* List of posted generic buffers (i.e. attached to the bd chain) */
    d_list_t            active_gen_list;

    /* List of returned generic buffers, may be used to immediate compensation this grq */
    d_list_t            aux_gen_list;

    lm_isle_t*          isles_pool; 
    /* Flag indicating that the grq needs to be compensated after generic buffers are allocated... */
    u8_t                grq_compensate_on_alloc;
    u8_t                grq_invloved_in_rss;

    u16_t               low_bds_threshold;
    u16_t               high_bds_threshold;

    s16_t               number_of_isles_delta;
    s32_t               gen_bufs_in_isles_delta;

    /* statistics */
    u16_t               max_grqs_per_dpc;     /* maximum grqs compensated in dpc */
    u16_t               num_grqs_last_dpc;
    u16_t               num_deficient;        /* number of times compensation wasn't complete */
    u16_t               avg_grqs_per_dpc;
    u32_t               avg_dpc_cnt;
    u32_t               sum_grqs_last_x_dpcs;
    u32_t               gen_bufs_compensated_from_bypass_only;
    u32_t               gen_bufs_compensated_till_low_threshold;
    u32_t               gen_bufs_collected_to_later_compensation;
} lm_tcp_grq_t;

/*******************************************************************************
 * L4 receive completion queue
 ******************************************************************************/
typedef struct _lm_tcp_rcq_t
{
    lm_bd_chain_t   bd_chain;

    /* points directly to the TOE Rx index in the USTORM part 
     * of the non-default status block */
    u16_t volatile      *hw_con_idx_ptr; 

    /* for RSS indirection table update synchronization */    
    u8_t                rss_update_pending; /* unused */
    u8_t                suspend_processing;
	u32_t				update_cid;
	u32_t				rss_update_stats_quiet;
	u32_t				rss_update_stats_sleeping;
	u32_t				rss_update_stats_delayed;
    u32_t               rss_update_processing_delayed;
    u32_t               rss_update_processing_continued;
    u32_t               rss_update_processing_max_continued;

    /* statistics */
    u16_t               max_cqes_per_dpc;
    u16_t               num_cqes_last_dpc;
    u16_t               avg_cqes_per_dpc;     
    u16_t               _pad16;
    u32_t               avg_dpc_cnt;
    u32_t               sum_cqes_last_x_dpcs; 

    lm_hc_sb_info_t     hc_sb_info;

} lm_tcp_rcq_t;

/*******************************************************************************
 * L4 send completion queue
 ******************************************************************************/
typedef struct _lm_tcp_scq_t
{
    lm_bd_chain_t   bd_chain;  

    /* points directly to the TOE Tx index in the CSTORM part 
     * of the non-default status block */
    u16_t volatile      *hw_con_idx_ptr;

    /* statistics */
    u16_t               max_cqes_per_dpc;
    u16_t               num_cqes_last_dpc;
    u16_t               avg_cqes_per_dpc;     
    u16_t               _pad16;
    u32_t               avg_dpc_cnt;
    u32_t               sum_cqes_last_x_dpcs; 

    lm_hc_sb_info_t     hc_sb_info;

} lm_tcp_scq_t;

/*******************************************************************************
 * states block - includes all offloaded states and possibly other offload 
 * information of a specific client.
 ******************************************************************************/
typedef struct _lm_state_block_t
{
    d_list_t                tcp_list;
    d_list_t                path_list;
    d_list_t                neigh_list;    
} lm_state_block_t;


typedef struct _lm_toe_statistics_t
{
    u32_t  total_ofld; /* cyclic counter of number of offloaded tcp states */
    u32_t  total_upld; /* cyclic counter of number of uploaded tcp states */   
    s32_t  total_indicated; /* cyclic counter of number of generic indications (sum of connections pending...) */
    s32_t  total_indicated_returned; /* cyclic counter of number of generic indications that have returned */

    /* aggregative per-connections statistics */
    u32_t rx_rq_complete_calls;     /* #RQ completion calls (total, copy + zero copy) */
    u32_t rx_rq_bufs_completed;     /* #RQ completion buffers */
    u64_t rx_bytes_completed_total; /* #RQ completion bytes */

    u32_t rx_accepted_indications;     /* #GRQ completion calls (indicate) */
    u32_t rx_bufs_indicated_accepted;  /* #GRQ completion buffers */
    u64_t rx_bytes_indicated_accepted; /* #GRQ completion bytes */

    u32_t rx_rejected_indications;     /* #failed or partially consumed indicate calls */
    u32_t rx_bufs_indicated_rejected;  /* #GRQ completion bytes */
    u64_t rx_bytes_indicated_rejected; /* #GRQ completion bytes */

    u32_t rx_zero_byte_recv_reqs;     /* #Zero byte receeive requests */
    u32_t rx_bufs_copied_grq;         /* #VBD copy bufs total */
    u32_t rx_bufs_copied_rq;          /* #VBD copy bufs total */
    u32_t _pad32_1;
    u64_t rx_bytes_copied_in_post;    /* #VBD copy bytes in post phase*/
    u64_t rx_bytes_copied_in_comp;    /* #VBD copy bytes in completion phase */
    u64_t rx_bytes_copied_in_process; /* #VBD copy bytes in process phase */

    /* post */
    u32_t rx_bufs_posted_total;
    u32_t rx_bufs_skipped_post;
    u64_t rx_bytes_skipped_post;
    u64_t rx_bytes_posted_total;

    /* push related */
    u64_t rx_bytes_skipped_push;
    u32_t rx_partially_completed_buf_cnt;

    /* abort */
    u32_t rx_buffer_aborted_cnt;

    u32_t tx_rq_complete_calls;
    u32_t tx_rq_bufs_completed;
    u64_t tx_bytes_posted_total;
    u64_t tx_bytes_completed_total;
    
    u32_t total_dbg_upld_requested;
    u32_t total_fin_upld_requested;
    u32_t total_rst_upld_requested;
    u32_t total_close_upld_requested;
    u32_t total_dbt_upld_requested;
    u32_t total_opt_upld_requested;
    u32_t total_big_isle_upld_requesed;
    u32_t total_many_isles_upld_requesed;
    u32_t total_upld_requested[L4_UPLOAD_REASON_MAX];
    u32_t con_state_on_upload[L4_TCP_CON_STATE_MAX];
    u32_t total_bytes_lost_on_upload;
    u32_t total_droped_non_empty_isles;
    u32_t total_droped_empty_isles;
    u32_t total_rx_post_blocked;
    u32_t total_zb_rx_post_blocked;
    u32_t total_cfc_delete_error;
    u32_t total_num_non_full_indications;
    u32_t total_aux_mem_success_allocations;
    u32_t total_aux_mem_failed_allocations;
    u32_t total_rx_abortion_under_flr;
    u32_t total_tx_abortion_under_flr;
    u32_t max_number_of_isles_in_single_con;
    u32_t total_aborive_disconnect_during_completion;
    u32_t total_pending_aborive_disconnect_completed;
    u32_t total_aborive_disconnect_completed;
    
    u64_t total_buffered_data;
} lm_toe_statistics_t;

typedef struct _lm_toe_isles_t
{
    s32_t gen_bufs_in_isles;
    s32_t max_gen_bufs_in_isles;
    s16_t number_of_isles;
    s16_t max_number_of_isles;
    u8_t  l4_decrease_archipelago;
    u8_t  __pad[3];
} lm_toe_isles_t;

/*******************************************************************************
 * toe info - all TOE (L4) information/data structures of the lm_device
 ******************************************************************************/
typedef struct _lm_toe_info_t
{
    struct _lm_device_t     *pdev;
    lm_state_block_t        state_blk;

    lm_toe_statistics_t     stats;
    lm_toe_isles_t          archipelago;

    lm_tcp_scq_t            scqs[MAX_L4_TX_CHAIN];
    lm_tcp_rcq_t            rcqs[MAX_L4_RX_CHAIN];
    lm_tcp_grq_t            grqs[MAX_L4_RX_CHAIN];

    u8_t                    indirection_table[TOE_INDIRECTION_TABLE_SIZE];
    u32_t                   rss_update_cnt; /* GilR 4/4/2006 - TBD on RSS indirection table update implementation */
    u32_t                   gen_buf_size;   /* The size of a generic buffer based on gen_buf_min_size and mtu */

    u8_t                    state;
    #define                 LM_TOE_STATE_NONE       0
    #define                 LM_TOE_STATE_INIT       1
    #define                 LM_TOE_STATE_NORMAL     2

    /* Once a generic indication succeeded and the buffers are given to the client we have to choose whether we want
     * to give a window-update immediately (short-loop) or wait for the buffer to return (long-loop). The mode is determined
     * by a set of rules in the UM related to the generic buffer pool and its state. The UM sets this parameter for the lm, 
     * and at each indication the lm checks which mode it is in, marks the generic buffer and gives a window-update accordingly  */
    u8_t                    update_window_mode;
    #define                 LM_TOE_UPDATE_MODE_LONG_LOOP  0
    #define                 LM_TOE_UPDATE_MODE_SHORT_LOOP 1

    /* This field is used to indicate that certain events have occured in TOE. Should be updated under TOE-LOCK */
    u8_t                    toe_events;
    #define                 LM_TOE_EVENT_WINDOW_DECREASE 0x1
    u8_t                    __pad[1];

    lm_toe_integrity_info_t integrity_info;

    /* Slow-path data for toe-rss (common and not per connection, therefore located here! ) */
    struct toe_rss_update_ramrod_data * rss_update_data;
    lm_address_t                        rss_update_data_phys;
} lm_toe_info_t;


#endif /* _LM_L4ST_H */
