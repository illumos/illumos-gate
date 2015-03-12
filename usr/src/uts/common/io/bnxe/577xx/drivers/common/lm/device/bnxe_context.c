
/*
functions for managing Chip per-connection context
*/
#include "context.h"
#include "command.h"
#include "cdu_def.h"
#include "bd_chain.h"

/* returns a pionter to a connections chip context*/
void * lm_get_context(struct _lm_device_t *pdev, u32_t cid){

    void * ret = NULL;
    u32_t page,off;

    DbgBreakIf(cid > pdev->params.max_func_connections);
    DbgBreakIf(pdev->context_info->array[cid].invalid != LM_CONTEXT_VALID);

    /* calculate which context page the CID is on*/
    page = cid / (pdev->params.num_context_in_page);

    /* calculate at what offset inside the page CID is on*/
    off = cid % (pdev->params.num_context_in_page);

    /* now goto page,off */
    ret = (void*)((char*)pdev->vars.context_cdu_virt_addr_table[page] + (pdev->params.context_line_size * off));
    /* warrning, this assumes context line size is in chars, need to check!!!*/

    return ret;
}

/* same as above but returns phys address in 64 bit pointer */
u64_t lm_get_context_phys(struct _lm_device_t *pdev, u32_t cid){

    u64_t ret = 0;
    u32_t page,off;

    DbgBreakIf(cid > pdev->params.max_func_connections);
    DbgBreakIf(pdev->context_info->array[cid].invalid != LM_CONTEXT_VALID);

    /* calculate which context page the CID is on*/
    page = cid / (pdev->params.num_context_in_page);

    /* calculate at what offset inside the page CID is on*/
    off = cid % (pdev->params.num_context_in_page);

    /* now goto page,off */
    ret = (pdev->vars.context_cdu_phys_addr_table[page].as_u64 + (pdev->params.context_line_size * off));
    /* warrning, this assumes context line size is in chars, need to check!!!*/

    return ret;
}

extern u32_t LOG2(u32_t v);
static lm_status_t lm_setup_searcher_hash_info(struct _lm_device_t *pdev)
{
    u32_t                    num_con    = 0 ;
    u32_t                    alloc_size = 0 ;
    lm_context_info_t*       context    = NULL;
    lm_searcher_hash_info_t* hash_info  = NULL;
    int                      offset     = 0 ;

    /* sanity */
    if ( CHK_NULL(pdev) || CHK_NULL( pdev->context_info ) )
    {
        DbgBreakMsg("Invalid Parameters") ;
        return LM_STATUS_INVALID_PARAMETER ;
    }
    context   = pdev->context_info;
    hash_info = &context->searcher_hash;

    DbgBreakIf(!pdev->params.max_func_connections);

    if CHK_NULL( hash_info->searcher_table)
    {
        DbgBreakIf(!( hash_info->searcher_table));
        return LM_STATUS_FAILURE;
    }
    num_con    = pdev->params.max_func_connections;
    alloc_size = sizeof(lm_searcher_hash_entry_t) * num_con;
    mm_mem_zero(hash_info->searcher_table, alloc_size);

    /* init value for searcher key */
    // TODO: for now a fixed key, need to change at runtime
    *(u32_t *)(&hash_info->searcher_key[0])  = 0x63285672;
    *(u32_t *)(&hash_info->searcher_key[4])  = 0x24B8F2CC;
    *(u32_t *)(&hash_info->searcher_key[8])  = 0x223AEF9B;
    *(u32_t *)(&hash_info->searcher_key[12]) = 0x26001E3A;
    *(u32_t *)(&hash_info->searcher_key[16]) = 0x7AE91116;
    *(u32_t *)(&hash_info->searcher_key[20]) = 0x5CE5230B;
    *(u32_t *)(&hash_info->searcher_key[24]) = 0x298D8ADF;
    *(u32_t *)(&hash_info->searcher_key[28]) = 0x6EB0FF09;
    *(u32_t *)(&hash_info->searcher_key[32]) = 0x1830F82F;
    *(u32_t *)(&hash_info->searcher_key[36]) = 0x1E46BE7;

    /* Microsoft's example key */
//      *(u32_t *)(&hash_info->searcher_key[0]) = 0xda565a6d;
//      *(u32_t *)(&hash_info->searcher_key[4]) = 0xc20e5b25;
//      *(u32_t *)(&hash_info->searcher_key[8]) = 0x3d256741;
//      *(u32_t *)(&hash_info->searcher_key[12]) = 0xb08fa343;
//      *(u32_t *)(&hash_info->searcher_key[16]) = 0xcb2bcad0;
//      *(u32_t *)(&hash_info->searcher_key[20]) = 0xb4307bae;
//      *(u32_t *)(&hash_info->searcher_key[24]) = 0xa32dcb77;
//      *(u32_t *)(&hash_info->searcher_key[28]) = 0x0cf23080;
//      *(u32_t *)(&hash_info->searcher_key[32]) = 0x3bb7426a;
//      *(u32_t *)(&hash_info->searcher_key[36]) = 0xfa01acbe;

    /* init searcher_key_bits array */
    for (offset = 0; offset < 10; offset++)
    {
        int j,k;
        u32_t bitsOffset = 32*offset;
        u8_t _byte;

        for (j= 0; j < 4; j++)
        {
            _byte  = (u8_t)((*(u32_t *)(&hash_info->searcher_key[offset*4]) >> (j*8)) & 0xff);
            for (k = 0; k < 8; k++)
            {
                hash_info->searcher_key_bits[bitsOffset+(j*8)+k] = ((_byte<<(k%8))& 0x80) ? 1 : 0;
            }
        }
    }

    /* init value for num hash bits */
    hash_info->num_hash_bits = (u8_t)LOG2(num_con);

    return LM_STATUS_SUCCESS ;
}

static lm_status_t lm_alloc_searcher_hash_info(struct _lm_device_t *pdev)
{
    u32_t                    num_con    = 0 ;
    u32_t                    alloc_size = 0 ;
    lm_searcher_hash_info_t* hash_info  = NULL ;
    u8_t                     mm_cli_idx = 0 ;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    mm_cli_idx = LM_RESOURCE_COMMON;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_MAX);

    /* searcher is defined with per-function #connections */
    num_con    = pdev->params.max_func_connections;
    alloc_size = sizeof(lm_searcher_hash_entry_t) * num_con;

    hash_info  = &pdev->context_info->searcher_hash;

    if CHK_NULL(hash_info)
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    /* allocate searcher mirror hash table */
    hash_info->searcher_table = mm_alloc_mem(pdev, alloc_size, mm_cli_idx);

    if CHK_NULL( hash_info->searcher_table )
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return  LM_STATUS_RESOURCE ;
    }
    return LM_STATUS_SUCCESS ;
}

lm_status_t lm_init_cid_resc(struct _lm_device_t *pdev, u32_t cid)
{
    lm_cid_resc_t *cid_resc = NULL;
    int            i        = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    cid_resc = &pdev->context_info->array[cid].cid_resc;
    if CHK_NULL(cid_resc)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < ARRSIZE(cid_resc->cookies); i++)
    {
        cid_resc->cookies[i] = NULL;
    }

    cid_resc->cid_pending = LM_CID_STATE_VALID;
    lm_sp_req_manager_init(pdev, cid);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_setup_context_pool(struct _lm_device_t *pdev)
{
    u32_t                     num_con         = 0;
    lm_context_info_t *       context         = NULL ;
    u32_t                     i,j;
    struct lm_context_cookie* array           = NULL ;
    lm_searcher_hash_entry_t* searcher_table  = NULL ;

    if CHK_NULL(pdev)
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_INVALID_PARAMETER;
    }

    context = pdev->context_info;

    if CHK_NULL(context)
    {
        DbgBreakIf( context == NULL );
        return LM_STATUS_INVALID_PARAMETER;
    }

    num_con = pdev->params.max_func_connections;

    array           = context->array ;
    searcher_table  = context->searcher_hash.searcher_table ;

    mm_mem_zero( context, sizeof(lm_context_info_t) ) ;

    context->array                        = array ;
    context->searcher_hash.searcher_table = searcher_table ;

    context->proto_start[ETH_CONNECTION_TYPE]   = 0;
    context->proto_end  [ETH_CONNECTION_TYPE]   = pdev->params.max_eth_including_vfs_conns - 1;
    context->proto_start[TOE_CONNECTION_TYPE]   = context->proto_end  [ETH_CONNECTION_TYPE]   + 1;
    context->proto_end  [TOE_CONNECTION_TYPE]   = context->proto_start[TOE_CONNECTION_TYPE]   + pdev->params.max_func_toe_cons - 1;
    context->proto_start[RDMA_CONNECTION_TYPE]  = context->proto_end  [TOE_CONNECTION_TYPE]   + 1;
    context->proto_end  [RDMA_CONNECTION_TYPE]  = context->proto_start[RDMA_CONNECTION_TYPE]  + pdev->params.max_func_rdma_cons - 1;
    context->proto_start[ISCSI_CONNECTION_TYPE] = context->proto_end  [RDMA_CONNECTION_TYPE]  + 1;
    context->proto_end  [ISCSI_CONNECTION_TYPE] = context->proto_start[ISCSI_CONNECTION_TYPE] + pdev->params.max_func_iscsi_cons - 1;
    context->proto_start[FCOE_CONNECTION_TYPE]  = context->proto_end  [ISCSI_CONNECTION_TYPE] + 1;
    context->proto_end  [FCOE_CONNECTION_TYPE]  = context->proto_start[FCOE_CONNECTION_TYPE]  + pdev->params.max_func_fcoe_cons - 1;
    DbgBreakIf(context->proto_end[MAX_PROTO - 1] > pdev->params.max_func_connections -1);

    if CHK_NULL(context->array)
    {
        DbgBreakIf(!( context->array));
        return LM_STATUS_INVALID_PARAMETER;
    }

    mm_mem_zero(context->array, sizeof(struct lm_context_cookie)*num_con);

    ASSERT_STATIC( ARRSIZE(context->proto_start) == ARRSIZE(context->proto_end) );

    /* zero cookies and populate the free lists */
    for (i = 0; i < ARRSIZE(context->proto_start); i++ )
    {
        for (j = context->proto_start[i]; j <= context->proto_end[i]; j++)
        {
            context->array[j].next    = j+1;
            context->array[j].invalid = LM_CONTEXT_VALID;
            context->array[j].ip_type = 0;
            context->array[j].h_val   = 0;
            lm_init_cid_resc(pdev, j);
        }
        /* set the first free item if max_func_XX_cons > 0 */
        if (context->proto_start[i] <= context->proto_end[i]) {
            context->proto_ffree[i] = context->proto_start[i];
        }
        else
        {
            context->proto_ffree[i] = 0;
        }
        context->proto_pending[i] = 0;
        /* put 0 (end of freelist in the last entry for the proto */
        context->array[context->proto_end[i]].next = 0;
    }
    //The ETH cid doorbell space was remapped just fixing the pointers.
    for (j = context->proto_start[ETH_CONNECTION_TYPE]; j <= context->proto_end[ETH_CONNECTION_TYPE]; j++)
    {
#ifdef VF_INVOLVED
        if (IS_CHANNEL_VFDEV(pdev)) {
            context->array[j].cid_resc.mapped_cid_bar_addr =
                (volatile void *)((u8_t*)pdev->vars.mapped_bar_addr[BAR_0] + j*lm_vf_get_doorbell_size(pdev) + VF_BAR0_DB_OFFSET);
#ifdef __SunOS
            context->array[j].cid_resc.reg_handle = pdev->vars.reg_handle[BAR_0];
#endif /* __SunOS */
        } else
#endif /* VF_INVOLVED */
        {
            context->array[j].cid_resc.mapped_cid_bar_addr =
                (volatile void *)((u8_t*)pdev->vars.mapped_bar_addr[BAR_1] + j*LM_DQ_CID_SIZE);
#ifdef __SunOS
            context->array[j].cid_resc.reg_handle = pdev->vars.reg_handle[BAR_1];
#endif /* __SunOS */
        }
    }
    return lm_setup_searcher_hash_info(pdev) ;
}

/* context pool initializer */
lm_status_t lm_alloc_context_pool(struct _lm_device_t *pdev){

    u32_t               num_con    = 0 ;
    lm_context_info_t * context    = NULL ;
    u8_t                mm_cli_idx = 0;

    if CHK_NULL(pdev)
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_INVALID_PARAMETER ;
    }

    /* must not be called if allready initialized */
    if ERR_IF( NULL != pdev->context_info )
    {
        DbgBreakIf( pdev->context_info != NULL ) ;
        return LM_STATUS_FAILURE ;
    }

    mm_cli_idx = LM_RESOURCE_COMMON;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_MAX);

    /* number of context is per-function, the cdu has a per-port register that can be set to be higher than the max_func_connections, but
     * the amount of memory actually allocated for the CDU matches max_func_connections. */
    num_con = pdev->params.max_func_connections ;

    /* allocate context info and cookie array */
    context = mm_alloc_mem(pdev, sizeof(lm_context_info_t), mm_cli_idx);
    if CHK_NULL(context)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    /* allocate list entries */
    context->array = mm_alloc_mem(pdev, sizeof(struct lm_context_cookie)*num_con, mm_cli_idx);
    if CHK_NULL(context->array)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    /* initilize the lock */

    /* put the context where it belongs */
    pdev->context_info = context;

    /* init searcher hash info */
    return lm_alloc_searcher_hash_info(pdev);
    /* return success */
}

/* context pool release function */
void lm_release_context_pool(struct _lm_device_t *pdev){

    lm_context_info_t* context = NULL;
    u32_t i, j;

    /* must only be called if initialized */
    DbgBreakIf( pdev->context_info == NULL );

    /* first make a copy and kill the original refference */
    context            = pdev->context_info;
    pdev->context_info = NULL;

    /* free context cookie array
       sanity check: scan it and make sure it is empty */
    for (i=0; i<(pdev->params.max_func_connections); i++  )
    {
        for (j = 0; j < MAX_PROTO; j++)
        {
            DbgBreakIf( context->array[i].cid_resc.cookies[j] != NULL );
        }

        /* NirV: can't call from here, context_info is NULL */
        /*DbgBreakIf(lm_sp_req_manager_shutdown(pdev, i) != LM_STATUS_SUCCESS);*/
    }
    /* mm_free_mem(context->array); */

    /* sanity check - searcher mirror hash must be empty */
    DbgBreakIf(context->searcher_hash.num_tuples);

    /* de-initilize the lock? if in debug mode we can leave it taken to chatch errors */

    /* free context info */
    /* mm_free_mem(context); */


    /* return success */

}

static u32_t _lm_searcher_mirror_hash_calc(lm_searcher_hash_info_t *hash_info, lm_4tuple_t *tuple)
{
    u8_t  in_str[MAX_SEARCHER_IN_STR] = {0};
    u8_t* in_str_bits                 = hash_info->searcher_in_str_bits;
    u8_t* key_bits                    = hash_info->searcher_key_bits;
    u32_t in_bits                     = 0;
    u32_t result                      = 0;
    u16_t i                           = 0;
    u16_t j                           = 0;

    /* prepare input string */
    if (tuple->ip_type == LM_IP_TYPE_V4)
    {
        *(u32_t *)(&in_str[0])  = HTON32(tuple->src_ip[0]);
        *(u32_t *)(&in_str[4])  = HTON32(tuple->dst_ip[0]);
        *(u16_t *)(&in_str[8])  = tuple->src_port;
        *(u16_t *)(&in_str[10]) = tuple->dst_port;
        in_bits = 12 * 8;
    }
    else
    {
        *(u32_t *)(&in_str[0])   = HTON32(tuple->src_ip[0]);
        *(u32_t *)(&in_str[4])   = HTON32(tuple->src_ip[1]);
        *(u32_t *)(&in_str[8])   = HTON32(tuple->src_ip[2]);
        *(u32_t *)(&in_str[12])  = HTON32(tuple->src_ip[3]);

        *(u32_t *)(&in_str[16])  = HTON32(tuple->dst_ip[0]);
        *(u32_t *)(&in_str[20])  = HTON32(tuple->dst_ip[1]);
        *(u32_t *)(&in_str[24])  = HTON32(tuple->dst_ip[2]);
        *(u32_t *)(&in_str[28])  = HTON32(tuple->dst_ip[3]);

        *(u16_t *)(&in_str[32]) = tuple->src_port;
        *(u16_t *)(&in_str[34]) = tuple->dst_port;
        in_bits = 36 * 8;
    }

    /* prepare searcher_in_str_bits from in_str */
    for (i = 0; i < in_bits; i++)
    {
        /* 0x80 - the leftmost bit. */
        in_str_bits[i] = ((in_str[i/8]<<(i%8)) & 0x80) ? 1 : 0;
    }

    /* calc ToeplitzHash */
    for (i = 0; i < 32; i++)
    {
        u8_t h = 0;

        for (j = 0; j < in_bits; j++)
        {
            h ^= key_bits[i+j] & in_str_bits[j];
        }

        result |= (h<<(32-i-1));
    }

    return result;
}

/* assumption: CID lock NOT taken by caller */
lm_status_t lm_searcher_mirror_hash_insert(struct _lm_device_t *pdev, u32_t cid, lm_4tuple_t *tuple)
{
    lm_context_info_t        *context    = NULL;
    lm_searcher_hash_entry_t *hash_entry = NULL;
    u32_t                    h_val       = 0;
    u8_t temp_ipv6, temp_ipv4, temp_depth_ipv4, is_ipv4;
    lm_status_t              lm_status   = LM_STATUS_SUCCESS;
    #define SRC_HASH_DEPTH_TH 15 /* that is searcher's default MaxNumHops - 1 */

    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);

    context = pdev->context_info;
    is_ipv4 = (tuple->ip_type == LM_IP_TYPE_V4 ? 1 : 0);

    /* calc hash val */
    h_val = _lm_searcher_mirror_hash_calc(&context->searcher_hash, tuple);

    /* take only num_hash_bits LSBs */
    h_val &= ((1 << context->searcher_hash.num_hash_bits) - 1);

    /* init num_hash_bits in the searcher: if the h_val is all FFFFs - set it to 0 */
    if (h_val == ((1 << context->searcher_hash.num_hash_bits) - 1)) {
        h_val = 0;
    }

    /* get the hash entry */
    hash_entry = &context->searcher_hash.searcher_table[h_val];

    /* start the alg. to find if there is a place available in that entry */
    temp_ipv6 = hash_entry->num_ipv6 + (is_ipv4 ? 0 : 1);
    temp_ipv4 = hash_entry->num_ipv4 + is_ipv4;

    /* tempDepthIpv4 = max ( depthIpv4(H), roundup(tempIpv4/2) ) */
    temp_depth_ipv4 = (temp_ipv4 / 2) + (temp_ipv4 % 2);
    if (temp_depth_ipv4 < hash_entry->depth_ipv4) {
        temp_depth_ipv4 = hash_entry->depth_ipv4;
    }

    if (temp_depth_ipv4 + temp_ipv6 > SRC_HASH_DEPTH_TH) {
        /* each hash entry has SRC_HASH_DEPTH_TH available places.
         * each place can contain 1 ipv6 connection or 2 ipv4 connections */
        DbgBreakMsg("Reached searcher hash limit\n");
        lm_status = LM_STATUS_FAILURE;
    } else {
        hash_entry->num_ipv6 = temp_ipv6;
        hash_entry->num_ipv4 = temp_ipv4;
        hash_entry->depth_ipv4 = temp_depth_ipv4;

        /* for debug, save the max depth reached */
        if (context->searcher_hash.hash_depth_reached < hash_entry->depth_ipv4 + hash_entry->num_ipv6) {
            context->searcher_hash.hash_depth_reached = hash_entry->depth_ipv4 + hash_entry->num_ipv6;
        }
        context->searcher_hash.num_tuples++;

        /* remeber the IP type and h_val to know where and how much
         * to decrease upon CID recycling */
        DbgBreakIf(context->array[cid].ip_type); /* cid can't be inserted twice */
        context->array[cid].ip_type = tuple->ip_type;
        context->array[cid].h_val = h_val;
    }

    /* release spinlock */
    MM_RELEASE_CID_LOCK(pdev);

    return lm_status;
}

/* assumption: CID lock NOT taken by caller */
void lm_searcher_mirror_hash_remove(struct _lm_device_t *pdev, u32_t cid)
{
    lm_context_info_t        *context    = NULL;
    lm_searcher_hash_entry_t *hash_entry = NULL;
    u32_t                    h_val       = 0;

    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);

    context = pdev->context_info;

    if(!context->array[cid].ip_type) {
        /* i.e lm_searcher_mirror_hash_insert was not called for this cid */
        DbgMessage(pdev, WARN,
                   "not removing CID %d from SRC hash (hash insert was not called for this cid)\n"
                   ,cid);

        /* release spinlock */
        MM_RELEASE_CID_LOCK(pdev);

        return;
    }

    h_val = context->array[cid].h_val;
    hash_entry = &context->searcher_hash.searcher_table[h_val];

    if (context->array[cid].ip_type == LM_IP_TYPE_V6) {
        DbgBreakIf(!hash_entry->num_ipv6);
        hash_entry->num_ipv6--;
    }
    else
    {
        DbgBreakIf(!hash_entry->num_ipv4);
        hash_entry->num_ipv4--;
        if (hash_entry->num_ipv4 < hash_entry->depth_ipv4)
        {
            hash_entry->depth_ipv4 = hash_entry->num_ipv4;
        }
    }

    /* for debug */
    context->searcher_hash.num_tuples--;

    /* clear the entry of the context */
    context->array[cid].ip_type = 0;
    context->array[cid].h_val = 0;

    /* release spinlock */
    MM_RELEASE_CID_LOCK(pdev);
}

/*  allocate a free context by type
    returns CID in the out_cid param
    return LM_STATUS_SUCCESS for available cid
    LM_STATUS_RESOURCE if no cids are available
    LM_STATUS_PENDING if there is a pending cfc-delete cid
    takes the list spinlock */
lm_status_t lm_allocate_cid(struct _lm_device_t *pdev, u32_t type, void * cookie, s32_t * out_cid){

    lm_context_info_t  *context  = NULL;
    lm_status_t        lm_status = LM_STATUS_SUCCESS;
    u32_t              cid       = (u32_t)-1;
    lm_address_t       phy_addr  = {{0}} ;

    if ( CHK_NULL(out_cid) ||
         CHK_NULL(pdev) ||
         CHK_NULL(pdev->context_info) ||
         CHK_NULL(pdev->context_info->array) ||
         CHK_NULL(cookie) ||
         ERR_IF(type >= ARRSIZE(pdev->context_info->proto_pending)) )

    {
        DbgBreakIf(!out_cid) ;
        DbgBreakIf(!pdev);
        DbgBreakIf(!pdev->context_info);
        DbgBreakIf(!pdev->context_info->array);
        DbgBreakIf(!cookie);
        DbgBreakIf(type >= ARRSIZE(pdev->context_info->proto_pending)) ;
        return LM_STATUS_INVALID_PARAMETER ;
    }

    context = pdev->context_info;
    *out_cid = 0;
    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);

    // if the free list is empty return error
    if (context->proto_ffree[type]==0) {
        if ((pdev->params.cid_allocation_mode == LM_CID_ALLOC_REGULAR) || (context->proto_pending[type] == 0)) {
            // if the free list is empty AND the pending list is empty return error OR
            // the free list is empty and we're in the regular allocating mode
            lm_status = LM_STATUS_RESOURCE;
        }
        else
        {
            /* pop pendinglist entry and place cookie */
            /* we only use the cid to connect between the pending connection and this cid, but
             * the connection can't know of this cid before it is acually freed, for this reason
             * we return cid = 0, which means, 'pending' */
            cid = context->proto_pending[type];
            context->proto_pending[type] = context->array[cid].next;
            context->array[cid].next = 0;
            context->array[cid].cid_resc.cookies[type] = cookie;
            context->array[cid].cid_resc.cid_pending = LM_CID_STATE_PENDING;
            lm_sp_req_manager_init(pdev, cid);
            *out_cid = cid;

            /* make sure the first cid previous is set correctly*/
            cid = context->proto_pending[type];
            if (cid) {
                context->array[cid].prev = 0;
            }
            lm_status = LM_STATUS_PENDING;
        }
    }else{
        /* pop freelist entry and place cookie*/
        cid = context->proto_ffree[type];
        context->proto_ffree[type] = context->array[cid].next;
        context->array[cid].next = 0;
        context->array[cid].prev = 0;
        context->array[cid].cid_resc.cookies[type] = cookie;
        lm_sp_req_manager_init(pdev, cid);
        *out_cid = cid;
        lm_status = LM_STATUS_SUCCESS;
    }

    MM_RELEASE_CID_LOCK(pdev);

    if(LM_STATUS_SUCCESS == lm_status)
    {
        //If the function allocated a new free CID, (not pending) the function MmMapIoSpace will be called
        //to map the specific physical cid doorbell space to a virtual address.
        //In case of a pending CID, the map doorbell space will not be remapped. The pending CID will use
        //the old mapping cid doorbell space.
        phy_addr.as_u32.low = (pdev->hw_info.mem_base[BAR_1].as_u32.low) & 0xfffffff0;
        phy_addr.as_u32.high = pdev->hw_info.mem_base[BAR_1].as_u32.high;

        LM_INC64(&phy_addr,(cid*LM_DQ_CID_SIZE));

#ifdef __SunOS

        context->array[cid].cid_resc.mapped_cid_bar_addr =
#ifdef VF_INVOLVED
            (volatile void *)((u8_t*)pdev->vars.mapped_bar_addr[BAR_1] + cid*LM_DQ_CID_SIZE);
        context->array[cid].cid_resc.reg_handle = pdev->vars.reg_handle[BAR_1];
#else /* !VF_INVOLVED */
            (volatile void *)mm_map_io_space_solaris(pdev,
                                                     phy_addr,
                                                     BAR_1,
                                                     (cid * LM_DQ_CID_SIZE),
                                                     LM_DQ_CID_SIZE,
                                                     &context->array[cid].cid_resc.reg_handle);
#endif /* VF_INVOLVED */

#else /* !__SunOS */

        context->array[cid].cid_resc.mapped_cid_bar_addr =
#ifdef VF_INVOLVED
            (volatile void *)((u8_t*)pdev->vars.mapped_bar_addr[BAR_1] + cid*LM_DQ_CID_SIZE);
#else /* !VF_INVOLVED */
            (volatile void *)mm_map_io_space(pdev, phy_addr, LM_DQ_CID_SIZE);
#endif /* VF_INVOLVED */

#endif /* __SunOS */

        // If the mapping failed we will return LM_STATUS_RESOURCE and return the cid resource.
        if CHK_NULL(context->array[cid].cid_resc.mapped_cid_bar_addr)
        {
            DbgMessage(pdev, FATAL, "lm_allocate_cid: mm_map_io_space failed. address low=%d address high=%d\n", phy_addr.as_u32.low,phy_addr.as_u32.high );

            /* take spinlock */
            MM_ACQUIRE_CID_LOCK(pdev);
            /* return the cid to free list */
            context->array[cid].next = pdev->context_info->proto_ffree[type];
            context->proto_ffree[type] = cid;
            context->array[cid].invalid = LM_CONTEXT_VALID;
            MM_RELEASE_CID_LOCK(pdev);

            lm_status = LM_STATUS_RESOURCE;
            *out_cid =0;
        }
    }
    return lm_status;
}

void lm_cfc_delete(struct _lm_device_t *pdev, void *param)
{
    u32_t cid             = *((u32_t *)&param);
    u8_t  flr_in_progress = lm_fl_reset_is_inprogress(pdev);

    if ( CHK_NULL(pdev) ||
         ERR_IF(cid > pdev->params.max_func_connections) ||
         ERR_IF(pdev->context_info->array[cid].invalid != LM_CONTEXT_INVALID_WAIT) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(cid > pdev->params.max_func_connections);

        if (!flr_in_progress)
        {
            DbgBreakIf(pdev->context_info->array[cid].invalid != LM_CONTEXT_INVALID_WAIT);
        }
        else
        {
            DbgMessage(pdev, FATAL, "lm_cfc_delete: invalid %d for cid=%d\n", pdev->context_info->array[cid].invalid,cid);

            if (pdev->context_info->array[cid].invalid != LM_CONTEXT_INVALID_DELETE)
            {
                DbgBreakIf(1);
            }
        }
    }

    DbgMessage(pdev, WARN, "lm_cfc_delete: cid=0x%x\n",cid);
    pdev->context_info->array[cid].invalid = LM_CONTEXT_INVALID_DELETE;

    if (lm_fl_reset_is_inprogress(pdev))
    {
         lm_recycle_cid(pdev, cid);
    }
    else
    {
        /* use common bit */
        lm_command_post(pdev,
                        cid,
                        RAMROD_CMD_ID_COMMON_CFC_DEL,
                        CMD_PRIORITY_NORMAL,
                        NONE_CONNECTION_TYPE,
                        0 );
    }
    return;
}

/* free a context
   takes the list spinlock */
void lm_free_cid(struct _lm_device_t *pdev, u32_t type, u32_t cid, u8_t notify_fw){
    u32_t delay_time  = 0;
    u32_t curr_cid    = 0;
    u8_t  recycle_now = 0;
    u8_t  proto_idx   = 0;

    if ( CHK_NULL(pdev) ||
         CHK_NULL(pdev->context_info) ||
         ERR_IF(type >= ARRSIZE(pdev->context_info->proto_end)) ||
         ERR_IF(cid > (pdev->context_info->proto_end[type])) ||
         ERR_IF(cid < (pdev->context_info->proto_start[type])) ||
         (!lm_fl_reset_is_inprogress(pdev) && (pdev->context_info->array[cid].invalid != LM_CONTEXT_VALID)))
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(!pdev->context_info);
        DbgBreakIf(type >= ARRSIZE(pdev->context_info->proto_end));
        DbgBreakIf(cid > (pdev->context_info->proto_end[type]));
        DbgBreakIf(cid < (pdev->context_info->proto_start[type]));
        DbgBreakIf(pdev->context_info->array[cid].invalid != LM_CONTEXT_VALID);
        return;
    }
    MM_ACQUIRE_CID_LOCK(pdev);

    for (proto_idx = 0; proto_idx < MAX_PROTO; proto_idx++)
    {
        DbgBreakIf(pdev->context_info->array[cid].cid_resc.cookies[proto_idx]);
    }

    lm_sp_req_manager_shutdown(pdev, cid);

    if (notify_fw)
    {
        /* Vladz: Added in order to optimize CID release in DOS */
#if !(defined(DOS) || defined(__LINUX))
        delay_time = LM_FREE_CID_DELAY_TIME(pdev);
#else
        delay_time = 0;
#endif

        pdev->context_info->array[cid].invalid = LM_CONTEXT_INVALID_WAIT;

        recycle_now = FALSE;
        /* add the cid to proto-pending: it'll be freed soon when cfc-delete is done */
        curr_cid = pdev->context_info->proto_pending[type];
        pdev->context_info->array[cid].next = curr_cid;
        pdev->context_info->array[cid].prev = 0;
        if (curr_cid != 0)
        {
            pdev->context_info->array[curr_cid].prev = cid;
        }
        pdev->context_info->proto_pending[type] = cid;
    }
    else
    {
        pdev->context_info->array[cid].invalid = LM_CONTEXT_INVALID_DELETE;
        recycle_now = TRUE;
        /* If we're recylcing now, there's no point in adding it to the pending list */
    }

    MM_RELEASE_CID_LOCK(pdev);

    if (recycle_now) {
        lm_recycle_cid(pdev, cid);
    }
    else
    {
        if (type == TOE_CONNECTION_TYPE)
        {
            DbgMessage(pdev, WARN, "lm_free_cid: CFC delete: cid=0x%x\n",cid);
            lm_cfc_delete(pdev,*((void **)&cid));
        }
        else
        {
            DbgMessage(pdev, WARN, "lm_free_cid: schedule CFC delete: cid=0x%x\n",cid);
            mm_schedule_task(pdev,delay_time,lm_cfc_delete,*((void **)&cid));
        }
    }

}

void lm_recycle_cid(struct _lm_device_t *pdev, u32_t cid){

    u32_t type = MAX_PROTO+1;
    u32_t prev_cid, next_cid;
    u32_t i;
    u8_t  call_cb = TRUE;

    if ( CHK_NULL(pdev) ||
         ERR_IF(pdev->context_info->array[cid].invalid != LM_CONTEXT_INVALID_DELETE) ||
         ERR_IF(cid > pdev->params.max_func_connections) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(pdev->context_info->array[cid].invalid != LM_CONTEXT_INVALID_DELETE);
        DbgBreakIf(cid > pdev->params.max_func_connections);
        return;
    }

    for (i=0; i < MAX_PROTO; i++ ) {
        if ((cid >= pdev->context_info->proto_start[i]) && (cid <= pdev->context_info->proto_end[i]))
        {
            type = i;
            break;
        }
    }
    if ERR_IF(type >= ARRSIZE(pdev->context_info->proto_pending))
    {
        DbgBreakIf(type >= ARRSIZE(pdev->context_info->proto_pending)) ;
        return;
    }
    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);
#ifdef _VBD_
    if ((type == TOE_CONNECTION_TYPE) && (pdev->ofld_info.l4_params.ticks_per_second != 0))
    {
        pdev->vars.last_recycling_timestamp = mm_get_current_time(pdev) * 1000 / pdev->ofld_info.l4_params.ticks_per_second; /*time in ms*/
    }
#endif
    /* If no cookie is waiting on this cid extract from pending and push enrty into the freelist */
    if (pdev->context_info->array[cid].cid_resc.cid_pending == FALSE) {
        /* take the cid out of the proto_pending cids if it's there */
        prev_cid = pdev->context_info->array[cid].prev;
        next_cid = pdev->context_info->array[cid].next;
        if (prev_cid) {
            pdev->context_info->array[prev_cid].next = next_cid;
        }
        if (next_cid) {
            pdev->context_info->array[next_cid].prev = prev_cid;
        }
        if (pdev->context_info->proto_pending[type] == cid) {
            DbgBreakIf(prev_cid != 0);
            pdev->context_info->proto_pending[type] = next_cid;
        }
        pdev->context_info->array[cid].prev = pdev->context_info->array[cid].next = 0;
        /* add to free list */
        pdev->context_info->array[cid].next = pdev->context_info->proto_ffree[type];
        pdev->context_info->array[cid].invalid = LM_CONTEXT_VALID;
        pdev->context_info->array[cid].cfc_delete_cnt = 0;
        pdev->context_info->proto_ffree[type] = cid;
        call_cb = FALSE; /* no one is waiting on this... */
        //free virtual memory for cids not in use.
#ifndef VF_INVOLVED
        mm_unmap_io_space(pdev,(void *)pdev->context_info->array[cid].cid_resc.mapped_cid_bar_addr, LM_DQ_CID_SIZE);
#endif
    }
    else
    {
        /* No need to extract from pending - it's not there. */

        /* NirV: we still can't set cid_resc.cid_pending to false, */
        /* will be possible only in the callback */

        pdev->context_info->array[cid].invalid = LM_CONTEXT_VALID;
        call_cb = TRUE;
    }

    /* time to clear the active bit (cdu-validation ) we can only do this after cfc-delete has completed, at this point, invalid==LM_CONTEXT_VALID */
    lm_set_cdu_validation_data(pdev, cid, TRUE /* Invalidate */);


    /* rlease spinlock */
    MM_RELEASE_CID_LOCK(pdev);

    /* call here the cid recycle callback of that
       protocol type if such cb exists*/
    if (pdev->cid_recycled_callbacks[type] && call_cb) {
        pdev->cid_recycled_callbacks[type](pdev, pdev->context_info->array[cid].cid_resc.cookies[type], cid);
    }

    return;
}

/* lookup the protocol cookie for a given CID
   does not take a lock
   will DbgBreakIf( if the CID is not allocated. */
void * lm_cid_cookie(struct _lm_device_t *pdev, u32_t type, u32_t cid){

    if ( CHK_NULL(pdev) ||
         CHK_NULL(pdev->context_info) ||
         ERR_IF(type >= MAX_PROTO) ||
         ERR_IF(cid > (pdev->context_info->proto_end[MAX_PROTO - 1])) ||
         CHK_NULL(pdev->context_info->array[cid].cid_resc.cookies[type]) ||
         ERR_IF(pdev->context_info->array[cid].invalid != LM_CONTEXT_VALID) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(!pdev->context_info);
        DbgBreakIf(type >= MAX_PROTO);
        DbgBreakIf(cid > (pdev->context_info->proto_end[MAX_PROTO - 1]));
        DbgBreakIf(pdev->context_info->array[cid].invalid != LM_CONTEXT_VALID);
    }

    if (pdev->context_info->array[cid].cid_resc.cookies[type] == NULL)
    {
        return NULL;
    }


    /* if the cid is pending, return null */
    if (pdev->context_info->array[cid].cid_resc.cid_pending != LM_CID_STATE_VALID)
    {
        return NULL;
    }

    return pdev->context_info->array[cid].cid_resc.cookies[type];
}

/* lookup the protocol cid_resc for a given CID
   does not take a lock
   will DbgBreakIf( if the CID is not allocated */
lm_cid_resc_t * lm_cid_resc(struct _lm_device_t *pdev, u32_t cid){

    if ( CHK_NULL(pdev) ||
         CHK_NULL(pdev->context_info) ||
         ERR_IF(cid > (pdev->context_info->proto_end[MAX_PROTO - 1])) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(!pdev->context_info);
        DbgBreakIf(cid > (pdev->context_info->proto_end[MAX_PROTO - 1]));
    }

    return &pdev->context_info->array[cid].cid_resc;
}

u8_t lm_map_cid_to_proto(struct _lm_device_t * pdev, u32_t cid)
{
    u8_t type = MAX_PROTO+1;
    u8_t i;

    if (!pdev || cid > pdev->params.max_func_connections) {
        return type;
    }

    for (i=0; i < MAX_PROTO; i++ ) {
        if ((cid >= pdev->context_info->proto_start[i]) && (cid <= pdev->context_info->proto_end[i]))  {
            type = i;
            break;
        }
    }
    return type;
}

void lm_init_connection_context(struct _lm_device_t *pdev, u32_t const sw_cid, u8_t sb_id)
{
    struct eth_context * context      = NULL;

    if ( CHK_NULL(pdev) ||
         ERR_IF(sw_cid < PFDEV(pdev)->context_info->proto_start[ETH_CONNECTION_TYPE]) ||
         ERR_IF(sw_cid > PFDEV(pdev)->context_info->proto_end[ETH_CONNECTION_TYPE]) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(sw_cid < PFDEV(pdev)->context_info->proto_start[ETH_CONNECTION_TYPE]); /* first legal NIC CID */
        DbgBreakIf(sw_cid > PFDEV(pdev)->context_info->proto_end[ETH_CONNECTION_TYPE]);   /* last legal NIC CID */
    }

    context = lm_get_context(PFDEV(pdev), VF_TO_PF_CID(pdev,sw_cid));

    mm_mem_zero( context, sizeof(struct eth_context) ) ;

    /* calculate the cdu-validation value. */
    lm_set_cdu_validation_data(pdev, VF_TO_PF_CID(pdev,sw_cid), FALSE /* don't invalidate */);

}

lm_status_t
lm_set_cid_resc(
    IN struct _lm_device_t *pdev,
    IN u32_t type,
    IN void *cookie,
    IN u32_t cid)
{
    lm_status_t     lm_status  = LM_STATUS_SUCCESS;
    lm_cid_resc_t   *cid_resc  = NULL;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);

    cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        MM_RELEASE_CID_LOCK(pdev);
        return LM_STATUS_INVALID_PARAMETER;
    }

    cid_resc->cookies[type] = cookie;

    /* rlease spinlock */
    MM_RELEASE_CID_LOCK(pdev);

    return lm_status;
}

lm_status_t
lm_free_cid_resc(
    IN    struct _lm_device_t *pdev,
    IN    u32_t type,
    IN    u32_t cid,
    IN    u8_t notify_fw)
{
    lm_cid_resc_t   *cid_resc = NULL;
    u8_t            proto_idx = 0;


    if (CHK_NULL(pdev) || (cid == 0))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);

    cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        MM_RELEASE_CID_LOCK(pdev);
        return LM_STATUS_INVALID_PARAMETER;
    }

    cid_resc->cookies[type] = NULL;

    while ((proto_idx < MAX_PROTO) && (cid_resc->cookies[proto_idx] == NULL))
    {
        proto_idx++;
    }
    /* rlease spinlock */
    MM_RELEASE_CID_LOCK(pdev);

    if (proto_idx == MAX_PROTO)
    {
        /* We'll call lm_map_cid_to_proto() to compute the appropriate type that was associated with that CID,
         * this is done to avoid assert upon race scenarios in which the last cookie resource that gets freed is not from the type of the CID */
        lm_free_cid(pdev, lm_map_cid_to_proto(pdev, cid), cid, notify_fw);
    }

    return LM_STATUS_SUCCESS;
}



lm_sp_req_manager_t *
lm_cid_sp_req_mgr(
    IN struct _lm_device_t *pdev,
    IN u32_t cid
    )
{
    lm_cid_resc_t   *cid_resc   = NULL;

    if CHK_NULL(pdev)
    {
        return NULL;
    }

    cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        return NULL;
    }

    return &cid_resc->sp_req_mgr;
}



lm_cid_state_enum
lm_cid_state(
    IN struct _lm_device_t *pdev,
    IN u32_t cid
    )
{
    lm_cid_resc_t   *cid_resc   = NULL;

    if CHK_NULL(pdev)
    {
        return LM_CID_STATE_ERROR;
    }

    cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        return LM_CID_STATE_ERROR;
    }

    return (lm_cid_state_enum)cid_resc->cid_pending;
}



lm_status_t
lm_set_cid_state(
    IN struct _lm_device_t *pdev,
    IN u32_t cid,
    IN lm_cid_state_enum state
    )
{
    lm_cid_resc_t   *cid_resc   = NULL;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* take spinlock */
    MM_ACQUIRE_CID_LOCK(pdev);

    cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        MM_RELEASE_CID_LOCK(pdev);
        return LM_STATUS_INVALID_PARAMETER;
    }

    cid_resc->cid_pending = state;

    /* rlease spinlock */
    MM_RELEASE_CID_LOCK(pdev);

    return LM_STATUS_SUCCESS;
}

/**
 * sets the CDU validation data to be valid for a given cid
 *
 * @param pdev - the physical device handle
 * @param cid - the context of this cid will be initialized with the cdu validataion data
 *
 * @return lm_status_t
 */
lm_status_t lm_set_cdu_validation_data(struct _lm_device_t *pdev, s32_t cid, u8_t invalidate)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    void        *context        = NULL;
    u8_t        *cdu_reserved   = NULL; /* Pointer to the actual location of cdu_reserved field according to protocol */
    u8_t        *cdu_usage      = NULL; /* Pointer to the actual location of cdu_usage field according to protocol */
    u8_t        proto_type      = 0;

    context = lm_get_context(PFDEV(pdev), cid);

    if (!context) {
        return LM_STATUS_FAILURE;
    }

    proto_type = lm_map_cid_to_proto(PFDEV(pdev), cid);

    switch (proto_type) {
    case TOE_CONNECTION_TYPE:
        cdu_reserved = &((struct toe_context *)context)->xstorm_ag_context.cdu_reserved;
        cdu_usage = &(((struct toe_context *)context)->ustorm_ag_context.cdu_usage);
        break;
    case ETH_CONNECTION_TYPE:
        cdu_reserved = &(((struct eth_context *)context)->xstorm_ag_context.cdu_reserved);
        cdu_usage =  &(((struct eth_context *)context)->ustorm_ag_context.cdu_usage);
        break;
    case ISCSI_CONNECTION_TYPE:
        cdu_reserved = &(((struct iscsi_context *)context)->xstorm_ag_context.cdu_reserved);
        cdu_usage = &(((struct iscsi_context *)context)->ustorm_ag_context.cdu_usage);
        break;
    case FCOE_CONNECTION_TYPE:
        cdu_reserved = &(((struct fcoe_context *)context)->xstorm_ag_context.cdu_reserved);
        cdu_usage = &(((struct fcoe_context *)context)->ustorm_ag_context.cdu_usage);
        break;
    default:
        lm_status = LM_STATUS_FAILURE;
        break;
    }

    if (cdu_reserved && cdu_usage) {
        if (invalidate) {
            *cdu_reserved = CDU_RSRVD_INVALIDATE_CONTEXT_VALUE(*cdu_reserved);
            *cdu_usage    = CDU_RSRVD_INVALIDATE_CONTEXT_VALUE(*cdu_usage);
        } else {
            *cdu_reserved = CDU_RSRVD_VALUE_TYPE_A(HW_CID(pdev, cid), CDU_REGION_NUMBER_XCM_AG, proto_type);
            *cdu_usage    = CDU_RSRVD_VALUE_TYPE_A(HW_CID(pdev, cid), CDU_REGION_NUMBER_UCM_AG, proto_type);
        }
    }

    return lm_status;
}


lm_status_t lm_get_context_size(struct _lm_device_t *pdev, s32_t * context_size)
{
    *context_size = LM_CONTEXT_SIZE;
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_set_con_state(struct _lm_device_t *pdev, u32_t cid, u32_t state)
{
    lm_cid_resc_t * cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    cid_resc->con_state = state;
    
    return LM_STATUS_SUCCESS;
}

u32_t lm_get_con_state(struct _lm_device_t *pdev, u32_t cid)
{
    const lm_cid_resc_t * cid_resc = lm_cid_resc(pdev, cid);

    if CHK_NULL(cid_resc)
    {
        return LM_CON_STATE_CLOSE;
    }

    return cid_resc->con_state;
}


