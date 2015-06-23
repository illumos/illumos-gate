/*******************************************************************************
 * lm_l5st.h - L5 lm data structures 
 ******************************************************************************/
#ifndef _LM_L5ST_H
#define _LM_L5ST_H


#include "everest_iscsi_constants.h"
#include "57xx_fcoe_constants.h"
#include "57xx_iscsi_constants.h"
#include "57xx_iscsi_rfc_constants.h"

#include "lm_l4st.h"


/* utility macros */
#define SET_FIELD(fieldName, mask, newVal) ((fieldName) = (((fieldName) & ~mask) | (((newVal) << mask ## _SHIFT) & mask)))
#define GET_FIELD(fieldName, mask) (((fieldName) & mask) >> mask ## _SHIFT)


#define ISCSI_LICENSE_CONNECTION_LIMIT (0xffff)     /* TODO: add iSCSI licensing support */

/*This is needed because the BD chain has not been set yet*/
/* The number of bds (EQEs) per page including the last bd which is used as
 * a pointer to the next bd page. */
#define ISCSI_EQES_PER_PAGE(_is_next_ptr_needed)    (USABLE_BDS_PER_PAGE(sizeof(struct iscsi_kcqe),_is_next_ptr_needed))
#define FCOE_EQES_PER_PAGE(_is_next_ptr_needed)     (USABLE_BDS_PER_PAGE(sizeof(struct fcoe_kcqe),_is_next_ptr_needed)) 


/* offset within a EQ page of the next page address */
#define NEXT_EQ_PAGE_ADDRESS_OFFSET	(LM_PAGE_SIZE - sizeof(struct iscsi_kcqe)) 

/* max number of eq chains, everst convention */
#define MAX_EQ_CHAIN                (ISCSI_NUM_OF_CQS*8) /* per function */

/* max EQ pages limitation */
#define MAX_EQ_PAGES                (256)


/* The number of useable bds per page.  This number does not include
 * the last bd at the end of the page. */
//#define MAX_EQ_BD_PER_PAGE          ((u32_t) (ISCSI_EQES_PER_PAGE - 1))

#define MAX_EQ_SIZE_FCOE(_is_next_ptr_needed)		            (MAX_EQ_PAGES * (FCOE_EQES_PER_PAGE(_is_next_ptr_needed) -1))
#define MAX_EQ_SIZE_ISCSI(_is_next_ptr_needed)		            (MAX_EQ_PAGES * (ISCSI_EQES_PER_PAGE(_is_next_ptr_needed) -1))
/* number of bits to shift to edjeust the page_size from the kwqe_init2 to 0 */
#define ISCSI_PAGE_BITS_SHIFT       (8)

/* layer mask value in the KCQEs */
#define KCQE_FLAGS_LAYER_MASK_L6    (ISCSI_KWQE_LAYER_CODE<<4)

/* pbl data */
typedef struct _lm_iscsi_pbl_t
{
	void            *base_virt;
    lm_address_t	base_phy;
	u32_t			base_size;	/* size allocated in bytes */

    lm_address_t	*pbl_phys_table_virt;
    lm_address_t	pbl_phys_table_phys;
    void            *pbl_virt_table;
	u32_t			pbl_size;	/* size allocated in bytes */
	u32_t			pbl_entries;/* number of entries in PBL */
} lm_iscsi_pbl_t;



typedef struct _lm_eq_addr_t
{
    u8_t          b_allocated;
    u32_t         prev_mem_size;
    void          *bd_chain_virt;      /* virt addr of first page of the chain */           
    lm_address_t  bd_chain_phy;        /* phys addr of first page of the chain */     
}lm_eq_addr_t;

typedef struct _lm_eq_addr_save_t
{
    lm_eq_addr_t    eq_addr[MAX_EQ_CHAIN];
}lm_eq_addr_save_t;

/*******************************************************************************
 * iSCSI info that will be allocated in the bind phase.
 * This is the only parameters that stays valid when iscsi goes to hibernate.
 ******************************************************************************/
typedef struct _lm_iscsi_info_bind_alloc_t
{
    u8_t	    *global_buff_base_virt;
    lm_address_t    global_buff_base_phy;
}lm_iscsi_info_bind_alloc_t;

typedef struct _lm_iscsi_statistics_t
{
    u32_t  total_ofld; /* cyclic counter of number of offloaded tcp states */
    u32_t  total_upld; /* cyclic counter of number of uploaded tcp states */   
}lm_iscsi_statistics_t;

/*******************************************************************************
 * iSCSI info that will be allocated in the bind phase.
 * These parameters become not valid when iscsi goes to hibernate.
 ******************************************************************************/
typedef struct _lm_iscsi_info_real_time_t
{
    lm_state_block_t    state_blk;
    d_list_t            iscsi_list;

	u32_t			num_of_tasks;
    u8_t			num_of_cqs;
    u32_t			cq_size;
    u16_t			hq_size;

    lm_eq_chain_t	eq_chain[MAX_EQ_CHAIN];
    #define LM_SC_EQ(_pdev, _idx)             (_pdev)->iscsi_info.run_time.eq_chain[_idx]

    /* L5 eq */
    u8_t l5_eq_chain_cnt;         /* number of L5 eq chains. currently equals num_of_cqs equals 1 */
    u8_t l5_eq_base_chain_idx;    /* L5 eq base chain Where do the L5 status block start */ 
    u16_t _pad_l5_eq;
    u32_t l5_eq_max_chain_cnt; /* registry param --> 32 bit */
    #define LM_SC_EQ_BASE_CHAIN_INDEX(pdev)           ((pdev)->iscsi_info.run_time.l5_eq_base_chain_idx)    /* that is first L5 SB */
    #define LM_SC_EQ_CHAIN_CNT(pdev)                  ((pdev)->iscsi_info.run_time.l5_eq_chain_cnt)
    #define LM_SC_MAX_CHAIN_CNT(pdev)                  ((pdev)->iscsi_info.run_time.l5_eq_max_chain_cnt)


    /* 'for loop' macros on L5 eq chains  */
    #define LM_SC_FOREACH_EQ_IDX(pdev, eq_idx)  \
        for ((eq_idx) = (pdev)->iscsi_info.run_time.l5_eq_base_chain_idx; (eq_idx) < (u32_t)((pdev)->iscsi_info.run_time.l5_eq_base_chain_idx + (pdev)->iscsi_info.run_time.l5_eq_chain_cnt); (eq_idx)++)

    lm_iscsi_statistics_t stats;
}lm_iscsi_info_run_time_t;
/*******************************************************************************
 * iSCSI info.
 ******************************************************************************/
typedef struct _lm_iscsi_info_t
{
    struct _lm_device_t *pdev;
    // Paramters that stay valid in D3 and are allocated in bind time.
    lm_iscsi_info_bind_alloc_t  bind;
    lm_eq_addr_save_t           eq_addr_save;
    #define LM_EQ_ADDR_SAVE_SC(_pdev, _idx)             (_pdev)->iscsi_info.eq_addr_save.eq_addr[_idx]
    // Paramters that are not valid in D3 and are allocated after bind time.
    lm_iscsi_info_run_time_t    run_time;
} lm_iscsi_info_t;


struct iscsi_update_ramrod_cached_params
{
	struct iscsi_kwqe_conn_update kwqe;
};


typedef union _lm_iscsi_slow_path_phys_data_t
{
    struct iscsi_context iscsi_ctx; /* used by query slow path request */
    struct iscsi_update_ramrod_cached_params update_ctx; /* used by update slow path request */

} lm_iscsi_slow_path_phys_data_t;


typedef struct _lm_iscsi_slow_path_data_t {
    lm_iscsi_slow_path_phys_data_t  * virt_addr;
    lm_address_t                    phys_addr;    
}lm_iscsi_slow_path_data_t ;


typedef struct _lm_iscsi_slow_path_request_t
{
    lm_sp_req_common_t           sp_req_common;
    lm_iscsi_slow_path_data_t    sp_req_data;

    u32_t    type;
    #define SP_REQUEST_SC_INIT                        0
    #define SP_REQUEST_SC_ADD_NEW_CONNECTION          1
    #define SP_REQUEST_SC_UPDATE                      2
    #define SP_REQUEST_SC_TERMINATE_OFFLOAD           3
    #define SP_REQUEST_SC_TERMINATE1_OFFLOAD          4
    #define SP_REQUEST_SC_QUERY                       5

    lm_status_t status; /* request completion status */    
} lm_iscsi_slow_path_request_t;


typedef struct _lm_iscsi_state_t
{
    lm_state_header_t               hdr;
    struct iscsi_context*           ctx_virt;
    lm_address_t                    ctx_phys;
    u32_t                           cid;    
    u16_t                           iscsi_conn_id;  /* Drivers connection ID. */
    u8_t                            b_keep_resources;
    u8_t                            b_resources_allocated;
    
	lm_iscsi_slow_path_data_t       sp_req_data;

    void                            *db_data;
    lm_address_t                    phys_db_data;

    lm_iscsi_pbl_t                  task_array;
    lm_iscsi_pbl_t                  r2tq;
    lm_iscsi_pbl_t                  hq;

    //iscsi_kwqe_t                    **pending_kwqes;
    struct iscsi_kwqe_conn_offload1      pending_ofld1;
    struct iscsi_kwqe_conn_offload2      pending_ofld2;
    struct iscsi_kwqe_conn_offload3      pending_ofld3;


} lm_iscsi_state_t;


/* RAMRODs used for FCOE */
typedef union _lm_fcoe_slow_path_phys_data_t
{
    struct fcoe_init_ramrod_params                  fcoe_init;
    struct fcoe_conn_offload_ramrod_params          fcoe_ofld;
    struct fcoe_conn_enable_disable_ramrod_params   fcoe_enable;
    struct fcoe_stat_ramrod_params                  fcoe_stat;
} lm_fcoe_slow_path_phys_data_t;



typedef struct _lm_fcoe_state_t
{
    lm_state_header_t               hdr;
    struct fcoe_context*            ctx_virt;
    lm_address_t                    ctx_phys;

    u32_t                           cid;    
    u16_t                           fcoe_conn_id;  /* Drivers connection ID. */

    struct fcoe_kwqe_conn_offload1      ofld1;
    struct fcoe_kwqe_conn_offload2      ofld2;
    struct fcoe_kwqe_conn_offload3      ofld3;
    struct fcoe_kwqe_conn_offload4      ofld4;
} lm_fcoe_state_t;






/*******************************************************************************
 * FCoE info that will be allocated in the bind phase.
 * This is the only parameters that stays valid when FCoE goes to hibernate.
 ******************************************************************************/

/* pbl data */
typedef struct _lm_fcoe_pbl_t
{
    u8_t            allocated; /*For D3 case and better debugging*/
    lm_address_t    *pbl_phys_table_virt;
    lm_address_t    pbl_phys_table_phys;
    void            *pbl_virt_table;
    u32_t           pbl_size;	/* size allocated in bytes */
    u32_t           pbl_entries;/* number of entries in PBL */
} lm_fcoe_pbl_t;

typedef struct _lm_fcoe_info_bind_alloc_t
{
    lm_fcoe_pbl_t   pbl[MAX_EQ_CHAIN];
    #define LM_FC_PBL(_pdev, _idx)             ((_pdev)->fcoe_info.bind.pbl[_idx])

    /* FCOE Miniport guarantees that they don't post more than once KWQE at a time, 
     * so there's no need to allocate per-connection ramrod buffer, A single fcoe per-client 
     * ramrod buffer (pdev->fcoe_info.bind.ramrod_mem_phys) can be used for all KWQEs.*/
    void            *ramrod_mem_virt;
    lm_address_t    ramrod_mem_phys;
}lm_fcoe_info_bind_alloc_t;

/*******************************************************************************
 * FCoE info that will be allocated in the bind phase.
 * These parameters become not valid when FCoE goes to hibernate.
 ******************************************************************************/
typedef struct _lm_fcoe_info_run_time_t
{
    lm_state_block_t        state_blk;
    lm_eq_chain_t	        eq_chain[MAX_EQ_CHAIN];
    #define LM_FC_EQ(_pdev, _idx)             (_pdev)->fcoe_info.run_time.eq_chain[_idx]

    u8_t            fc_eq_base_chain_idx;
    u8_t			num_of_cqs;

    d_list_t            fcoe_list;
    
    #define LM_FC_FOREACH_EQ_IDX(pdev, eq_idx)  \
        for ((eq_idx) = (pdev)->fcoe_info.run_time.fc_eq_base_chain_idx; (eq_idx) < (u32_t)((pdev)->fcoe_info.run_time.fc_eq_base_chain_idx + (pdev)->fcoe_info.run_time.num_of_cqs); (eq_idx)++)
}lm_fcoe_info_run_time_t;
/*******************************************************************************
 * FCOE info.
 ******************************************************************************/
typedef struct _lm_fcoe_info_t
{
    struct _lm_device_t     *pdev;

    // Paramters that stay valid in D3 and are allocated in bind time.
    lm_fcoe_info_bind_alloc_t   bind;
    lm_eq_addr_save_t           eq_addr_save;
    #define LM_EQ_ADDR_SAVE_FC(_pdev, _idx)             (_pdev)->fcoe_info.eq_addr_save.eq_addr[_idx]
    // Paramters that are not valid in D3 and are allocated after bind time.
    lm_fcoe_info_run_time_t     run_time;
} lm_fcoe_info_t;

#endif
