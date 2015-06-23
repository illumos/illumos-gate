/*******************************************************************************
* lm_l5if.h - L5 lm interface 
******************************************************************************/
#ifndef _LM_L5IF_H
#define _LM_L5IF_H



//#include "57xx_iscsi_hsi_diag.h"

	
lm_status_t
lm_sc_alloc_resc(
    IN struct _lm_device_t *pdev
    );


lm_status_t
lm_sc_clear_resc(
    IN struct _lm_device_t *pdev
    );

lm_status_t
lm_sc_ooo_chain_establish(
    IN struct _lm_device_t *pdev);

lm_status_t
lm_fc_clear_resc(
    IN struct _lm_device_t *pdev
    );


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_sc_clear_d0_resc(
    IN struct _lm_device_t *pdev,
    const u8_t cid
    );

lm_status_t
lm_sc_init(
    IN struct _lm_device_t *pdev,
    IN struct iscsi_kwqe_init1  *req1, 
    IN struct iscsi_kwqe_init2  *req2
    );


lm_status_t
lm_fc_clear_d0_resc(
    IN struct _lm_device_t *pdev,
    const u8_t cid
    );

lm_status_t
lm_fc_init(
    IN struct _lm_device_t          *pdev,
    IN struct fcoe_kwqe_init1       *init1,
    IN struct fcoe_kwqe_init2       *init2,
    IN struct fcoe_kwqe_init3       *init3);


void
lm_fc_recycle_cid_cb(
    struct _lm_device_t     *pdev,
    void                    *cookie,
    s32_t                   cid);


void 
lm_fc_comp_cb(
    struct _lm_device_t *pdev, 
    struct sq_pending_command *pending);


lm_status_t
lm_fc_alloc_resc(
    IN struct _lm_device_t          *pdev);


/**
 * @description
 * Returns the max FCOE task supported. 
 * In oreder to know the max task enabled refer to 
 * pdev->params.max_fcoe_task 
 * @param pdev 
 * 
 * @return u32_t 
 */
u32_t
lm_fc_max_fcoe_task_sup(
    IN struct _lm_device_t          *pdev);

lm_status_t
lm_sc_alloc_con_phys_mem(
    IN struct _lm_device_t          *pdev,
    IN lm_iscsi_state_t             *iscsi);

lm_status_t
lm_sc_alloc_con_resc(
    IN struct _lm_device_t          *pdev,
    IN lm_iscsi_state_t             *iscsi,
    IN struct iscsi_kwqe_conn_offload1     *req1,
    IN struct iscsi_kwqe_conn_offload2     *req2,
    IN struct iscsi_kwqe_conn_offload3     *req3
    );

lm_status_t
lm_fc_alloc_con_resc(
    IN struct _lm_device_t          *pdev,
    IN lm_fcoe_state_t              *fcoe);


void lm_sc_free_con_phys_mem(
    IN struct _lm_device_t *pdev,
    IN lm_iscsi_state_t *iscsi
    );

lm_status_t
lm_sc_free_con_resc(
    IN struct _lm_device_t *pdev,
    IN lm_iscsi_state_t *iscsi
    );

lm_status_t
lm_fc_free_con_resc(
    IN struct _lm_device_t          *pdev,
    IN lm_fcoe_state_t              *fcoe);


void
lm_sc_init_sp_req_type(
    IN struct _lm_device_t        * pdev, 
    IN lm_iscsi_state_t             * tcp, 
    IN lm_iscsi_slow_path_request_t * lm_req, 
    IN void                       * req_input_data
    );



lm_status_t
lm_sc_post_slow_path_request(
    IN  struct _lm_device_t *pdev,
    IN  lm_iscsi_state_t *iscsi,
    IN  lm_iscsi_slow_path_request_t *request
    );



lm_status_t
lm_sc_init_iscsi_state(
    IN struct _lm_device_t *pdev,
    IN lm_state_block_t *state_blk,
    IN lm_iscsi_state_t *iscsi
    );


void
lm_sc_del_iscsi_state(
    IN struct _lm_device_t *pdev,
    IN lm_iscsi_state_t *iscsi
    );

void
lm_fc_del_fcoe_state(
    struct _lm_device_t             *pdev,
    lm_fcoe_state_t                 *fcoe);

lm_status_t
lm_fc_init_fcoe_state(
    struct _lm_device_t             *pdev,
    lm_state_block_t                *state_blk,
    lm_fcoe_state_t                 *fcoe);


lm_status_t lm_sc_init_iscsi_context(
    IN struct _lm_device_t      *pdev,
    IN lm_iscsi_state_t         *iscsi,
    struct iscsi_kwqe_conn_offload1     *req1,
    struct iscsi_kwqe_conn_offload2    *req2,
    struct iscsi_kwqe_conn_offload3    *req3
    );


lm_status_t
lm_fc_init_fcoe_context(
    IN struct _lm_device_t          *pdev,
    IN lm_fcoe_state_t              *fcoe);


void
lm_sc_service_eq_intr(
    IN struct _lm_device_t *pdev,
    IN u8_t sb_idx
    );

void
lm_fc_service_eq_intr(
    IN struct _lm_device_t          *pdev,
    IN u8_t                         sb_idx);


u8_t
lm_sc_is_eq_completion(
    IN struct _lm_device_t *pdev,
    IN u8_t sb_idx
    );


u8_t
lm_fc_is_eq_completion(
    IN struct _lm_device_t *pdev,
    IN u8_t sb_idx
    );


lm_status_t
lm_sc_complete_l4_ofld_request(
	IN struct _lm_device_t *pdev,
	IN struct iscsi_kcqe *kcqe
	);


lm_status_t 
lm_sc_complete_l4_upload_request(
	IN struct _lm_device_t *pdev,
	IN u8_t                 op_code,
	IN u32_t                cid);
    

lm_status_t
lm_sc_complete_slow_path_request(
	IN struct _lm_device_t *pdev,
	IN struct iscsi_kcqe *kcqe
	);


lm_status_t
lm_fc_complete_slow_path_request(
    IN struct _lm_device_t          *pdev,
    IN struct fcoe_kcqe             *kcqe);


lm_status_t
lm_fc_post_offload_ramrod(
    struct _lm_device_t             *pdev,
    lm_fcoe_state_t                 *fcoe);

lm_status_t
lm_fc_post_enable_ramrod(
    struct _lm_device_t                     *pdev,
    lm_fcoe_state_t                         *fcoe,
    struct fcoe_kwqe_conn_enable_disable    *enable);

lm_status_t
lm_fc_post_disable_ramrod(
    struct _lm_device_t                    *pdev,
    lm_fcoe_state_t                        *fcoe,
    struct fcoe_kwqe_conn_enable_disable   *destroy);


lm_status_t
lm_fc_post_destroy_ramrod(
    struct _lm_device_t             *pdev);


lm_status_t
lm_fc_post_stat_ramrod(
    struct _lm_device_t         *pdev,
    struct fcoe_kwqe_stat       *stat);

lm_status_t
lm_fc_post_terminate_ramrod(
    struct _lm_device_t             *pdev,
    lm_fcoe_state_t                 *fcoe);

#endif /* _LM_L5IF_H */
