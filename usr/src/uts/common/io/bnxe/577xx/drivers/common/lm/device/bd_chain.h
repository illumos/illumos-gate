
/*******************************************************************************
* bd_chain.h - bd chain interface 
*******************************************************************************/
#ifndef _BD_CHAIN_H
#define _BD_CHAIN_H

/* The number of bd's per page including the last bd which is used as
 * a pointer to the next bd page. */
#define BD_PER_PAGE(bd_size)        (LM_PAGE_SIZE/(bd_size))

/* Number of bds that are used for the 'next' prt. The next ptr is constant size (sizeof lm_bd_chain_next). however, 
 * we will always work with 'full' bds. So if the bd-size is smaller than the next-ptr, we will use several, if it is
 * larger, we will use a full one (no partial bds...) The equation 1+((next_bd_size-1)/bd_size) gives us the number of bds
 * we need for this purpose. */
#define NUM_BDS_USED_FOR_NEXT_PTR(bd_size,is_chain_mode) ((is_chain_mode)? (1 + ((sizeof(lm_bd_chain_next)-1) / (bd_size))): 0)

/* The number of useable bd's per page.  This number does not include the bds at the end of the page used for the 'next-bd' */
#define USABLE_BDS_PER_PAGE(bd_size,is_chain_mode)    ((u32_t) (BD_PER_PAGE(bd_size)-NUM_BDS_USED_FOR_NEXT_PTR(bd_size,is_chain_mode)))


/* return number of available bds, i.e. _usable_ not produced bds */
__inline static u16_t lm_bd_chain_avail_bds(lm_bd_chain_t* bd_chain)
{
    return bd_chain->bd_left;
}

/* return the cyclic prod idx */
__inline static u16_t lm_bd_chain_prod_idx(lm_bd_chain_t* bd_chain)
{
    return bd_chain->prod_idx;
}

/* return the cyclic cons idx */
__inline static u16_t lm_bd_chain_cons_idx(lm_bd_chain_t* bd_chain)
{
    return bd_chain->cons_idx;
}

/* return the usable_bds_per_page */
__inline static u16_t lm_bd_chain_usable_bds_per_page(lm_bd_chain_t* bd_chain)
{
    return bd_chain->usable_bds_per_page;
}

/* return the page_cnt */
__inline static u16_t lm_bd_chain_page_cnt(lm_bd_chain_t* bd_chain)
{
    return bd_chain->page_cnt;
}

/* return the bds_per_page */
__inline static u16_t lm_bd_chain_bds_per_page(lm_bd_chain_t* bd_chain)
{
    return bd_chain->bds_per_page;
}

/* return the bds_per_page_mask */
__inline static u16_t lm_bd_chain_bds_per_page_mask(lm_bd_chain_t* bd_chain)
{
    return bd_chain->bds_per_page_mask;
}

/* return the bds_skip_eop */
__inline static u16_t lm_bd_chain_bds_skip_eop(lm_bd_chain_t* bd_chain)
{
    return bd_chain->bds_skip_eop;
}

/* return empty state */
__inline static u8_t lm_bd_chain_is_empty(lm_bd_chain_t* bd_chain)
{
    return (bd_chain->bd_left == 0);
}

/* return full state */
__inline static u8_t lm_bd_chain_is_full(lm_bd_chain_t* bd_chain)
{
    return (bd_chain->bd_left == bd_chain->capacity);
}

/* returns the phys addr of the page of given page_idx. (page_idx >= 0) */
__inline static lm_address_t lm_bd_chain_phys_addr(lm_bd_chain_t* bd_chain, u8_t page_idx)
{
    lm_address_t mem_phys = bd_chain->bd_chain_phy;
    u8_t idx;

    page_idx = page_idx % bd_chain->page_cnt;

    if (bd_chain->b_is_chain_mode)
    {
        /* TODO: assumption that memory is contiguous.. */
        for(idx = 0; idx < page_idx; idx++)
        {
            /* Increment mem_phy to the next page. */
            LM_INC64(&mem_phys, LM_PAGE_SIZE);
        }
    }
    else
    {
        mem_phys = bd_chain->pbl_phys_addr_table[page_idx];
    }
    return mem_phys;
}


/*******************************************************************************
 * Description:
 * afrer allocating the ring, this func fixes the last BD pointers at the 
 * end of a page to point to the first BD in the next page.
 * Return:
 ******************************************************************************/
__inline static void lm_bd_chain_set_next_ptrs(lm_bd_chain_t * bd_chain)
{
    lm_address_t start_mem_phy;
    lm_address_t mem_phy;
    lm_bd_chain_next * next_bd;
    u8_t *start_mem_virt;
    u8_t *mem_virt;
    u16_t idx;

    mem_virt = bd_chain->bd_chain_virt;
    mem_phy = bd_chain->bd_chain_phy;

    DbgBreakIf(
        ((u32_t) PTR_SUB(mem_virt, 0) & LM_PAGE_MASK) !=
            (mem_phy.as_u32.low & LM_PAGE_MASK));

    DbgBreakIf(!bd_chain->b_is_chain_mode);

    /* make sure all known bds structure equals to lm_bd_chain_next structure before  */
    /* tx bd */
    ASSERT_STATIC(OFFSETOF(struct eth_tx_next_bd, addr_hi) == OFFSETOF(lm_bd_chain_next, addr_hi)) ;    
    ASSERT_STATIC(OFFSETOF(struct eth_tx_next_bd, addr_lo) == OFFSETOF(lm_bd_chain_next, addr_lo)) ;
    ASSERT_STATIC(OFFSETOF(struct eth_tx_next_bd, reserved)== OFFSETOF(lm_bd_chain_next, reserved) ) ;

    /* rx bd */
    ASSERT_STATIC(OFFSETOF(struct eth_rx_bd_next_page, addr_hi) == OFFSETOF(lm_bd_chain_next, addr_hi)) ;    
    ASSERT_STATIC(OFFSETOF(struct eth_rx_bd_next_page, addr_lo) == OFFSETOF(lm_bd_chain_next, addr_lo)) ;
    ASSERT_STATIC(OFFSETOF(struct eth_rx_bd_next_page, reserved)== OFFSETOF(lm_bd_chain_next, reserved) ) ;

    /* rcq */
    ASSERT_STATIC(OFFSETOF(struct eth_rx_cqe_next_page, addr_hi) == OFFSETOF(lm_bd_chain_next, addr_hi)) ;    
    ASSERT_STATIC(OFFSETOF(struct eth_rx_cqe_next_page, addr_lo) == OFFSETOF(lm_bd_chain_next, addr_lo)) ;
    ASSERT_STATIC(OFFSETOF(struct eth_rx_cqe_next_page, reserved)== OFFSETOF(lm_bd_chain_next, reserved) ) ;

    /* Toe stuff */
    ASSERT_STATIC(OFFSETOF(struct toe_page_addr_bd, addr_hi) == OFFSETOF(lm_bd_chain_next, addr_hi)) ;    
    ASSERT_STATIC(OFFSETOF(struct toe_page_addr_bd, addr_lo) == OFFSETOF(lm_bd_chain_next, addr_lo)) ;
    ASSERT_STATIC(OFFSETOF(struct toe_page_addr_bd, reserved)== OFFSETOF(lm_bd_chain_next, reserved) ) ;

    start_mem_phy = mem_phy;
    start_mem_virt = mem_virt;

    for(idx = 0; idx < bd_chain->page_cnt-1; idx++)
    {
        if CHK_NULL(mem_virt)
        {
            DbgBreakIfAll(!mem_virt) ;
            return ;
        }

        /* Increment mem_phy to the next page. */
        LM_INC64(&mem_phy, LM_PAGE_SIZE);

        /* Initialize the physical address of the next bd chain. */
        next_bd = (lm_bd_chain_next *)(mem_virt + (bd_chain->bd_size) * (bd_chain->usable_bds_per_page));
        
        next_bd->addr_hi = mm_cpu_to_le32(mem_phy.as_u32.high);
        next_bd->addr_lo = mm_cpu_to_le32(mem_phy.as_u32.low);

        /* Initialize the virtual address of the next bd chain. */
        *((u8_t **) next_bd->reserved) =  mem_virt + LM_PAGE_SIZE;

        /* Move to the next bd chain. */
        mem_virt += LM_PAGE_SIZE;
    }

    next_bd = (lm_bd_chain_next *)(mem_virt + (bd_chain->bd_size) * (bd_chain->usable_bds_per_page));
    next_bd->addr_hi = mm_cpu_to_le32(start_mem_phy.as_u32.high);
    next_bd->addr_lo = mm_cpu_to_le32(start_mem_phy.as_u32.low);
    *((u8_t **) next_bd->reserved) = start_mem_virt;
} /* lm_bd_chain_set_next_ptrs */

/* setup bd chain.
 * - currently only physically contiguous chain format is supported
 * -  */

unsigned long log2_align(unsigned long n);

__inline static lm_status_t lm_bd_chain_add_page(
    struct _lm_device_t *pdev,
    lm_bd_chain_t*       bd_chain,
    void                *mem_virt,  /* ptr to caller pre-allocated buffer */
    lm_address_t         mem_phys,   /* phys addr of buffer */
    u8_t                 bd_size,    /* currently only 8 and 16 bytes are possible */
    u8_t                 is_chain_mode) /* Is the next pointer the last entry*/
{

    lm_bd_chain_next * next_bd;

    UNREFERENCED_PARAMETER_(pdev);

    DbgBreakIf((bd_chain->page_cnt + 1) * BD_PER_PAGE(bd_size) > 0xffff);
    if (is_chain_mode)
    {
        if (bd_chain->page_cnt) {
            u16_t page_index;
            DbgBreakIf(bd_chain->bd_size != bd_size);
            next_bd = (lm_bd_chain_next *)((u8_t*)bd_chain->bd_chain_virt + (bd_chain->bd_size) * (bd_chain->usable_bds_per_page));
            for (page_index = 0; page_index < bd_chain->page_cnt - 1; page_index++) {
                next_bd = (lm_bd_chain_next *)((u8_t*)(*(void **)(next_bd->reserved)) + (bd_chain->bd_size) * (bd_chain->usable_bds_per_page));        
            }
            next_bd->addr_hi = mm_cpu_to_le32(mem_phys.as_u32.high);
            next_bd->addr_lo = mm_cpu_to_le32(mem_phys.as_u32.low);
            *((u8_t **) next_bd->reserved) =  mem_virt;
            next_bd = (lm_bd_chain_next *)((u8_t*)mem_virt + (bd_chain->bd_size) * (bd_chain->usable_bds_per_page));        
            next_bd->addr_hi = mm_cpu_to_le32(bd_chain->bd_chain_phy.as_u32.high);
            next_bd->addr_lo = mm_cpu_to_le32(bd_chain->bd_chain_phy.as_u32.low);
            *((u8_t **) next_bd->reserved) =  bd_chain->bd_chain_virt;
        } else {
            bd_chain->bd_chain_phy = mem_phys;
            bd_chain->bd_chain_virt = mem_virt;
            bd_chain->bd_size = bd_size;
            bd_chain->bds_skip_eop = NUM_BDS_USED_FOR_NEXT_PTR(bd_size,is_chain_mode);
            bd_chain->usable_bds_per_page = USABLE_BDS_PER_PAGE(bd_size,is_chain_mode);
            bd_chain->bds_per_page = BD_PER_PAGE(bd_size);
            bd_chain->b_is_chain_mode = TRUE;
            bd_chain->num_bd_to_sub   = 0;
            bd_chain->usable_bds_mask = bd_chain->usable_bds_per_page;

            /* we assume power of 2 for bd_chain->bds_per_page */
            DbgBreakIf(bd_chain->bds_per_page != log2_align((u32_t)bd_chain->bds_per_page));
            bd_chain->bds_per_page_mask = bd_chain->bds_per_page - 1;
            bd_chain->cons_idx = 0;
            bd_chain->prod_idx = 0;
            bd_chain->next_bd = bd_chain->bd_chain_virt;
            /* Initialize the physical address of the next bd chain. */
            next_bd = (lm_bd_chain_next *)((u8_t*)mem_virt + (bd_chain->bd_size) * (bd_chain->usable_bds_per_page));

            next_bd->addr_hi = mm_cpu_to_le32(mem_phys.as_u32.high);
            next_bd->addr_lo = mm_cpu_to_le32(mem_phys.as_u32.low);

            /* Initialize the virtual address of the next bd chain. */
            *((u8_t **) next_bd->reserved) =  mem_virt;
        }
    }
    else
    {
        //TODO: currently TOE only, implement for PBL
        //      add the physical address of the page to the next pbl_page_idx
        //      ensure that the pbl_virt in this case is valid..
        DbgBreak();
    }

    bd_chain->page_cnt++;
    bd_chain->capacity = bd_chain->page_cnt * bd_chain->usable_bds_per_page;         
    bd_chain->bd_left = bd_chain->capacity;

    return LM_STATUS_SUCCESS;
}

__inline static lm_status_t lm_bd_chain_setup(
    struct _lm_device_t *pdev,
    lm_bd_chain_t*       bd_chain,
    void                *mem_virt,  /* ptr to caller pre-allocated buffer */
    lm_address_t         mem_phys,   /* phys addr of buffer */
    u16_t                page_cnt,   /* #pages in given buffer */
    u8_t                 bd_size,    /* currently only 8 and 16 bytes are possible */
    u8_t                 is_full,   /* chain initial state (full or empty) */
    u8_t                 is_chain_mode) /* Is the next pointer the last entry*/   
{
    DbgBreakIf(page_cnt * BD_PER_PAGE(bd_size) > 0xffff);

    UNREFERENCED_PARAMETER_(pdev);

    bd_chain->bd_chain_phy = mem_phys;
    bd_chain->bd_chain_virt = mem_virt;
    bd_chain->bd_size = bd_size;
    bd_chain->bds_skip_eop = NUM_BDS_USED_FOR_NEXT_PTR(bd_size,is_chain_mode);
    bd_chain->usable_bds_per_page = USABLE_BDS_PER_PAGE(bd_size,is_chain_mode);
    bd_chain->bds_per_page = BD_PER_PAGE(bd_size);

    /* we assume power of 2 for bd_chain->bds_per_page */
    DbgBreakIf(bd_chain->bds_per_page != log2_align((u32_t)bd_chain->bds_per_page));
    bd_chain->bds_per_page_mask = bd_chain->bds_per_page - 1;

#ifdef __SunOS
    /*
     * This minor code change fixes a compiler error in SunStudio 12u1.  The
     * bug is that an "imulw $-0x80,..." is generated which wrecks the capacity
     * value specifically when initializing the FCoE EQ chain.  Shifting code
     * around and/or removing the deep inline access to this function will fix
     * the issue but would be a kludge.  Note that I've created this ifdef to
     * ensure someone doesn't come in later and merge these two lines together
     * thereby reverting it to what it was before.
     */
    bd_chain->capacity = page_cnt;
    bd_chain->capacity *= bd_chain->usable_bds_per_page;
#else
    bd_chain->capacity = page_cnt * bd_chain->usable_bds_per_page;
#endif
    bd_chain->page_cnt = page_cnt;
    bd_chain->next_bd = bd_chain->bd_chain_virt;
    bd_chain->cons_idx = 0;
    
    if(is_full) {
        bd_chain->prod_idx = page_cnt * bd_chain->bds_per_page;
        bd_chain->bd_left = 0;
    } else {
        bd_chain->prod_idx = 0;
        /* Don't count the last bd of a BD page.  A full BD chain must
         * have at least one empty entry.  */
        bd_chain->bd_left = bd_chain->capacity;
    }
    if(is_chain_mode) 
    {
        bd_chain->b_is_chain_mode = TRUE;
        bd_chain->num_bd_to_sub   = 0;
        bd_chain->usable_bds_mask = bd_chain->usable_bds_per_page;
        lm_bd_chain_set_next_ptrs(bd_chain);
    }

    return LM_STATUS_SUCCESS;
}

__inline static lm_status_t lm_bd_chain_pbl_set_ptrs(
    IN  void         *buf_base_virt,    /* ptr to caller pre-allocated buffer */
    IN  lm_address_t buf_base_phy,      /* phys addr of the pre-allocated buffer */
    IN  lm_address_t *pbl_phys_table,   /* ptr to caller pre-allocated buffer of phys pbl */
    IN  void         *pbl_virt_table,   /* ptr to caller pre-allocated buffer of virt pbl */
    IN  u32_t         pbl_entries       /* #pages in given buffer */
    )
{
	u32_t i;

	if (CHK_NULL(buf_base_virt) ||
        CHK_NULL(pbl_phys_table) ||
        CHK_NULL(pbl_virt_table) ||
        (pbl_entries == 0))
	{
        return LM_STATUS_INVALID_PARAMETER;
    }

	/* fill page table elements */
	for (i = 0; i < pbl_entries; i++)
    {
#ifdef BIG_ENDIAN
        pbl_phys_table[i].as_u32.low = mm_cpu_to_le32(buf_base_phy.as_u32.high);
        pbl_phys_table[i].as_u32.high = mm_cpu_to_le32(buf_base_phy.as_u32.low);
#else // LITTLE_ENDIAN
        pbl_phys_table[i].as_u64 = buf_base_phy.as_u64;
#endif

        *(void **)(((u8_t *)pbl_virt_table + (sizeof(void *) * i))) = buf_base_virt;

        /* Increment mem_phy to the next page. */
        /* TODO: assumption that memory is contiguous.. */
        LM_INC64(&buf_base_phy, LM_PAGE_SIZE);

        buf_base_virt = (u8_t *)buf_base_virt + LM_PAGE_SIZE;
     }

	return LM_STATUS_SUCCESS;
}


__inline static lm_status_t lm_bd_chain_pbl_setup(
    struct _lm_device_t *pdev,
    lm_bd_chain_t*       bd_chain,
    void                *mem_virt,           /* ptr to caller pre-allocated buffer */
    lm_address_t         mem_phys,           /* phys addr of buffer */
    void                *pbl_virt_table,     /* ptr to caller pre-allocated buffer of virt pbl */
    lm_address_t        *pbl_phys_table,     /* ptr to caller pre-allocated buffer of phys pbl */
    u16_t                page_cnt,           /* #pages in given buffer */
    u8_t                 bd_size,            /* currently only 8 and 16 bytes are possible */
    u8_t                 is_full)            /* chain initial state (full or empty) */
{
    lm_status_t lm_status;

    lm_status = lm_bd_chain_setup(pdev,
                                  bd_chain,
                                  mem_virt,
                                  mem_phys,
                                  page_cnt,
                                  bd_size,
                                  is_full,
                                  FALSE);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    //assign additional pbl members
    bd_chain->pbl_phys_addr_table = pbl_phys_table;
    bd_chain->pbl_virt_addr_table = pbl_virt_table;
    bd_chain->b_is_chain_mode     = FALSE;
    bd_chain->num_bd_to_sub       = 1;
    bd_chain->usable_bds_mask     = bd_chain->usable_bds_per_page - 1;
    // Upon first be consume or produce, page will be advanced,
    // so set the initial page index to the last one
    bd_chain->pbe_idx             = page_cnt - 1;

    lm_status = lm_bd_chain_pbl_set_ptrs(mem_virt,
                                         mem_phys,
                                         bd_chain->pbl_phys_addr_table,
                                         bd_chain->pbl_virt_addr_table,
                                         page_cnt);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    return LM_STATUS_SUCCESS;
}

/** Description
 *  Function resets a bd chain: initializes the bds to 'all zeros'
 *  chain remains valid though, (last bd points to the next page of the bd chain)
 */ 
__inline static void lm_bd_chain_reset(struct _lm_device_t * pdev, lm_bd_chain_t * bd_chain)    
{
    DbgBreakIf(!bd_chain->bd_chain_virt);
    /* FIXME: assumption that memory is contiguous.. */
    mm_memset(bd_chain->bd_chain_virt, 0, bd_chain->page_cnt * LM_PAGE_SIZE);
    if (bd_chain->b_is_chain_mode)
    {
        lm_bd_chain_setup(pdev,
                          bd_chain,
                          bd_chain->bd_chain_virt, 
                          bd_chain->bd_chain_phy,
                          bd_chain->page_cnt,
                          bd_chain->bd_size,
                          FALSE,
                          bd_chain->b_is_chain_mode);
    }
    else
    {
        lm_bd_chain_pbl_setup(pdev,
                              bd_chain,
                              bd_chain->bd_chain_virt,
                              bd_chain->bd_chain_phy,
                              bd_chain->pbl_virt_addr_table,
                              bd_chain->pbl_phys_addr_table,
                              bd_chain->page_cnt,
                              bd_chain->bd_size,
                              FALSE);
    }
}

/* Receives a bd_idx, pointer to bd and increases them. 
 * the physical address is the physical address of the base of the page
 * Assumptions: 
 * - virt is initialized with the virtual address of the current bd
 * - phys is initialized with the physical address of the current page
 */
__inline static void lm_bd_chain_incr_bd(
    lm_bd_chain_t     * bd_chain, 
    lm_address_t      * phys,
    void             ** virt,
    u16_t             * bd_idx)
{

    (*bd_idx)++;
    *virt = ((char *)*virt) + bd_chain->bd_size;

    if((*bd_idx & bd_chain->usable_bds_per_page) == bd_chain->usable_bds_per_page) {
        if (bd_chain->b_is_chain_mode) {
            lm_bd_chain_next *next_bd = (lm_bd_chain_next *)(*virt);
            (*bd_idx) += bd_chain->bds_skip_eop;
             *virt = *(void **)(next_bd->reserved);
             phys->as_u32.high = next_bd->addr_hi;
             phys->as_u32.low  = next_bd->addr_lo;
        } else {
            //TODO: currently TOE only, implement for PBL
            DbgBreak();
        }
    }

}

__inline static void lm_bd_advance_page(lm_bd_chain_t* bd_chain, u16_t *idx_to_inc)
{
    if (bd_chain->b_is_chain_mode)
    {
        lm_bd_chain_next *next_bd = (lm_bd_chain_next *)bd_chain->next_bd;
        bd_chain->next_bd = *(void **)(next_bd->reserved);
        *idx_to_inc += bd_chain->bds_skip_eop;
    }
    else
    {
        bd_chain->pbe_idx++;
        if (bd_chain->pbe_idx == bd_chain->page_cnt) {
            bd_chain->pbe_idx = 0;
        }
        bd_chain->next_bd = *(void **)((u8_t *)bd_chain->pbl_virt_addr_table + (sizeof(void *) * bd_chain->pbe_idx));
    }
}

/*******************************************************************************
* API For a bd-chain that the driver "Produces"  
*******************************************************************************/

/* update bds availabily.
 * - nbds - number of _usable_ consumed bds
 * - NOTE: the chain consumer idx+pointer are not maintained! */
__inline static void lm_bd_chain_bds_consumed(lm_bd_chain_t* bd_chain, u16_t nbds)
{
    bd_chain->bd_left += nbds; 
    DbgBreakIfFastPath(bd_chain->bd_left > bd_chain->capacity);
}

/* returns ptr to next _usable_ bd to be produced,
 * decreases bds availability by 1, and updates prod idx.
 * NOTE: special case for TOE: prod idx jumps to the next page only when the first bd of the next page is produced */
__inline static void *lm_toe_bd_chain_produce_bd(lm_bd_chain_t* bd_chain)
{
    void *ret_bd = NULL;
    u16_t prod_idx = 0;
    
    DbgBreakIf(!bd_chain->bd_left);

    prod_idx = bd_chain->prod_idx - bd_chain->num_bd_to_sub;
    if((prod_idx & bd_chain->usable_bds_mask) == bd_chain->usable_bds_mask) {
        lm_bd_advance_page(bd_chain, &bd_chain->prod_idx);
    }

    ret_bd = bd_chain->next_bd;
    bd_chain->bd_left--;
    bd_chain->prod_idx++;
    bd_chain->next_bd += bd_chain->bd_size;
      
    return ret_bd;
}

/* returns ptr to next _usable_ bd to be produced,
 * decreases bds availability by 1, and updates prod idx.
 */
__inline static void *lm_bd_chain_produce_bd(lm_bd_chain_t* bd_chain)
{
    void *ret_bd = NULL;
    u16_t prod_idx = 0;

    DbgBreakIfFastPath(!bd_chain->bd_left);

    ret_bd = bd_chain->next_bd;
    bd_chain->bd_left--;
    bd_chain->prod_idx++;
    bd_chain->next_bd += bd_chain->bd_size;

    prod_idx = bd_chain->prod_idx - bd_chain->num_bd_to_sub;
    if((prod_idx & bd_chain->usable_bds_mask) == bd_chain->usable_bds_mask) {
        lm_bd_advance_page(bd_chain, &bd_chain->prod_idx);
    }

    return ret_bd;
}


/*******************************************************************************
* API For a bd-chain that the driver "Consumes"  
*******************************************************************************/

/* returns ptr to next _usable_ bd to be consume,
 * increases bds availability by 1, and updates cons idx.
 * NOTE: cons idx jumps to the next page only when the first bd of the next page is consumed */
__inline static void *lm_toe_bd_chain_consume_bd(lm_bd_chain_t* bd_chain)
{
    void *ret_bd = NULL;
    u16_t cons_idx = 0;
    
    DbgBreakIf(bd_chain->bd_left == bd_chain->capacity);

    cons_idx = bd_chain->cons_idx - bd_chain->num_bd_to_sub;
    if((cons_idx & bd_chain->usable_bds_mask) == bd_chain->usable_bds_mask) {
        lm_bd_advance_page(bd_chain, &bd_chain->cons_idx);
    }
    ret_bd = bd_chain->next_bd;

    bd_chain->bd_left++;
    bd_chain->cons_idx++;
    bd_chain->next_bd += bd_chain->bd_size;
      
    return ret_bd;
}

__inline static void *lm_bd_chain_consume_bd(lm_bd_chain_t* bd_chain)
{
    void *ret_bd = NULL;
    u16_t cons_idx = 0;
    
    DbgBreakIfFastPath(bd_chain->bd_left == bd_chain->capacity);

    ret_bd = bd_chain->next_bd;

    bd_chain->bd_left++;
    bd_chain->cons_idx++;
    bd_chain->next_bd += bd_chain->bd_size;

    cons_idx = bd_chain->cons_idx - bd_chain->num_bd_to_sub;
    if((cons_idx & bd_chain->usable_bds_mask) == bd_chain->usable_bds_mask) {
        lm_bd_advance_page(bd_chain, &bd_chain->cons_idx);
    }
      
    return ret_bd;
}

/* returns a bd only if it is contiguous to the previously requested bd... otherwise NULL. 
 * The algorithm is based on the fact that we don't double-increase a consumer if we've reached the
 * end of the page. we have one call that is called when the next_bd points to the last_bd, in which case
 * we recognize that the next_bd is no longer contiguous, return NULL and move forward. The next call will 
 * return the next bd... 
 */
__inline static void *lm_bd_chain_consume_bd_contiguous(lm_bd_chain_t* bd_chain)
{
    void *ret_bd = NULL;
    u16_t cons_idx = 0;

    DbgBreakIf(bd_chain->bd_left == bd_chain->capacity);

    cons_idx = bd_chain->cons_idx - bd_chain->num_bd_to_sub;
    if((cons_idx & bd_chain->usable_bds_mask) == bd_chain->usable_bds_mask) {
        lm_bd_advance_page(bd_chain, &bd_chain->cons_idx);

        return NULL; /* we've just skipped the last bd... */
    }

    ret_bd = bd_chain->next_bd;

    bd_chain->bd_left++;
    bd_chain->cons_idx++;
    bd_chain->next_bd += bd_chain->bd_size;
      
    return ret_bd;
}



/* update bds availabily and prod idx.
 * - nbds - number of _usable_ produced bds
 * Special case for TOE, they need producer increased only if we've moved to the next page...  */
__inline static void lm_toe_bd_chain_bds_produced(lm_bd_chain_t* bd_chain, u16_t nbds)
{
    u16_t nbds_mod_usable_bds;
    u8_t next_bds = 0;    

    DbgBreakIfFastPath(bd_chain->bd_left < nbds);
    bd_chain->bd_left -= nbds; 

   /* perform the operation "nbds % bd_chain->usable_bds_per_page" manually
   (in order to avoid explicit modulo instruction that lead to very 
    expensive IDIV asm instruction) */
    nbds_mod_usable_bds = nbds;
    while (nbds_mod_usable_bds >= bd_chain->usable_bds_per_page) 
    {
        nbds_mod_usable_bds -= bd_chain->usable_bds_per_page;
    }

    /* calculate the number of _next_ bds passed */
    next_bds += nbds / bd_chain->usable_bds_per_page;
    if(next_bds && ((bd_chain->prod_idx & bd_chain->bds_per_page_mask) == 0)) {
        next_bds--; /* special care here, this next bd will be counted only next time bds are produced */
    }
    if((bd_chain->prod_idx & bd_chain->bds_per_page_mask) + nbds_mod_usable_bds > bd_chain->usable_bds_per_page) {
        next_bds++;
    }

    /* update prod idx */
    bd_chain->prod_idx += nbds + next_bds * bd_chain->bds_skip_eop;

    DbgBreakIfFastPath((bd_chain->prod_idx & bd_chain->bds_per_page_mask) > bd_chain->usable_bds_per_page); /* assertion relevant to 8b bd chain */
    DbgBreakIfFastPath((bd_chain->prod_idx & bd_chain->bds_per_page_mask) == 0); /* GilR 5/13/2006 - this is currently the agreement with FW */
}

/* update bds availabily and prod idx.
 * - nbds - number of _usable_ produced bds */
__inline static void lm_bd_chain_bds_produced(lm_bd_chain_t* bd_chain, u16_t nbds)
{    
    u16_t nbds_mod_usable_bds;
    u8_t next_bds = 0;    
    
    DbgBreakIfFastPath(bd_chain->bd_left < nbds);
    bd_chain->bd_left -= nbds; 

    /* perform the operation "nbds % bd_chain->usable_bds_per_page" manually
   (in order to avoid explicit modulo instruction that lead to very 
    expensive IDIV asm instruction) */
    nbds_mod_usable_bds = nbds;
    while (nbds_mod_usable_bds >= bd_chain->usable_bds_per_page) 
    {
        nbds_mod_usable_bds -= bd_chain->usable_bds_per_page;
    }

    /* calculate the number of _next_ bds passed */
    next_bds += nbds / bd_chain->usable_bds_per_page;    
    if((bd_chain->prod_idx & bd_chain->bds_per_page_mask) + nbds_mod_usable_bds > bd_chain->usable_bds_per_page) {
        next_bds++;
    }

    /* update prod idx */
    bd_chain->prod_idx += nbds + next_bds * bd_chain->bds_skip_eop;    
}

/* lm_bd_chain_bd_produced - 
   a performance optimated version of lm_bd_chain_bds_produced:
   update bds availabily and prod idx, when only one bd is produced.
 */
__inline static void lm_bd_chain_bd_produced(lm_bd_chain_t* bd_chain)
{       
    DbgBreakIfFastPath(bd_chain->bd_left < 1);
    bd_chain->bd_left--; 

    /* if we passed a _next_ bd, increase prod_idx accordingly */    
    if((bd_chain->prod_idx & bd_chain->bds_per_page_mask) + 1 > bd_chain->usable_bds_per_page) {
        bd_chain->prod_idx += bd_chain->bds_skip_eop;    
    }

    /* update prod idx for the produced bd */
    bd_chain->prod_idx++; 
}

/* TRUE if all params in bd_chains are equal but the pointers */
__inline static u8_t lm_bd_chains_are_consistent( lm_bd_chain_t* bd_chain,
                                                  lm_bd_chain_t* bd_chain2 )
{
    const u32_t cmp_size = OFFSETOF(lm_bd_chain_t, reserved) - OFFSETOF(lm_bd_chain_t, page_cnt) ;
    u8_t        b_ret    = 0; 

    ASSERT_STATIC( OFFSETOF(lm_bd_chain_t, page_cnt) < OFFSETOF(lm_bd_chain_t, reserved)) ;

    b_ret = mm_memcmp( (u8_t*)bd_chain + OFFSETOF(lm_bd_chain_t, page_cnt),
                       (u8_t*)bd_chain2 + OFFSETOF(lm_bd_chain_t, page_cnt),
                       cmp_size );

    return b_ret;
}

#endif /* _BD_CHAIN_H */
