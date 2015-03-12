#ifndef _LM_SP_REQ_MGR_H
#define _LM_SP_REQ_MGR_H

#include "listq.h"

/*******************************************************************************
 * slow path request manager data structures
 ******************************************************************************/

/* Frward declaration */
struct _lm_device_t;

typedef struct _lm_sp_req_common_t
{
    s_list_entry_t	    link;
    void                *req_post_func; 
    void 	            *req_post_ctx;	  
    u32_t		        req_seq_number;
} lm_sp_req_common_t;

typedef lm_status_t (*req_post_function)(
    struct _lm_device_t *pdev,
    void *state_ctx,                        /* tcp_state / iscsi_state */
    lm_sp_req_common_t *sp_req);

typedef struct _lm_sp_req_manager_t
{
    s_list_t    pending_reqs;
    u32_t       req_seq_number;
    u8_t        blocked;
    /* ToDo: use instaed of tcpstate.sp_request */
    lm_sp_req_common_t  * posted_req;
    void                * sp_data_virt_addr;
    lm_address_t          sp_data_phys_addr;
} lm_sp_req_manager_t;



/*******************************************************************************
 * slow path request manager prototypes
 ******************************************************************************/
lm_status_t
lm_sp_req_manager_set_sp_data(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid,
    IN  void *virt_addr,
    IN  lm_address_t phys_addr
    );

lm_status_t
lm_sp_req_manager_init(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid
    );

lm_status_t
lm_sp_req_manager_shutdown(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid
    );

lm_status_t
lm_sp_req_manager_post(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid,
    IN  struct _lm_sp_req_common_t *sp_req
    );

lm_status_t
lm_sp_req_manager_complete(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid,
    IN  u32_t seq_num,
    OUT lm_sp_req_common_t **sp_req
    );

lm_status_t
lm_sp_req_manager_block(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid
    );

lm_status_t
lm_sp_req_manager_unblock(
    IN  struct _lm_device_t *pdev,
    IN  u32_t cid,
    OUT lm_sp_req_common_t **sp_req
    );


#endif /* _LM_SP_REQ_MGR_H */
