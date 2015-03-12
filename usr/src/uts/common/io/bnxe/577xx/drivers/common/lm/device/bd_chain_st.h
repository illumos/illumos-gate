
/*******************************************************************************
* bd_chain.h - bd chain interface 
*******************************************************************************/
#ifndef _BD_CHAIN_ST_H
#define _BD_CHAIN_ST_H

#include "lm_defs.h"

typedef struct _lm_bd_chain_next {
	u32_t addr_lo /* Single continuous buffer low pointer */;
	u32_t addr_hi /* Single continuous buffer high pointer */;
	u8_t reserved[8] /* keeps same size as other eth tx bd types */;
} lm_bd_chain_next ;


typedef struct _lm_bd_chain_t 
{
    void          *bd_chain_virt;      /* virt addr of first page of the chain */           
    lm_address_t  bd_chain_phy;        /* phys addr of first page of the chain */     
    char          *next_bd;            /* pointer to next bd to produce or consume */    
    u16_t         page_cnt;            /* number of chain pages */
    u16_t         capacity;            /* number of _usable_ bds (e.g. not including _next_ bds) */
    u16_t         bd_left;             /* number of not produced, _usable_ bds */
    u16_t         prod_idx;            /* index of next bd to produce (cyclic) */    
    u16_t         cons_idx;            /* index of next bd to consume (cyclic) */            
    u16_t         bds_per_page;        /* Number of bds per page */
    u16_t         bds_per_page_mask;   /* Mask of number of bds per page */
    u16_t         usable_bds_per_page; /* Number of usable bds in a page (taking into account last 16 bytes for 'next-ptr' */
    u8_t          bd_size;             /* currently 8 and 16 bytes are supported. ("next_bd" is always 18 bytes) */
    u8_t          bds_skip_eop;        /* num bds to skip at the end of the page due to the 'next pointer' */
    u8_t          reserved[2];    

    //PBL
    void          *pbl_virt_addr_table;/* virt table pbl */
    lm_address_t  *pbl_phys_addr_table;/* phys table pbl */
    u16_t         pbe_idx;             /* index of the current pbe page */
    u16_t         usable_bds_mask;     /* Mask used to check if end of page was reached */
    u8_t          b_is_chain_mode;     /* indicate if using bd_chain interface or pbl interface */
    u8_t          num_bd_to_sub;       /* Number of bds to subtract when checking if end of page was reached */
    u8_t          reserved1[2];
} lm_bd_chain_t;


typedef struct _lm_hc_sb_info_t
{
    u8_t hc_sb;
    u8_t hc_index_value;
    u16_t iro_dhc_offset;
} lm_hc_sb_info_t;


#endif /* _BD_CHAIN_ST_H */
