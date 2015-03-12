/*******************************************************************************
* mm_l5if.h - L5 mm interface 
******************************************************************************/
#ifndef _MM_L5IF_H
#define _MM_L5IF_H


/* per OS methods */
#if defined(DOS)

#elif defined(__LINUX)

#elif defined(_VBD_) || defined(_WINK_UDBG_) 

#elif defined(__USER_MODE_DEBUG)

#endif


/** Description:
 *  - 
 * Assumptions:
 *  - 
 *  - 
 */
lm_status_t
mm_sc_comp_l5_request(
    IN struct _lm_device_t *pdev,
    IN struct iscsi_kcqe *kcqes,
    IN u32_t num_kqes
    );

lm_status_t
mm_fc_comp_request(
        IN struct _lm_device_t      *pdev,
        IN struct fcoe_kcqe         *kcqes,
        IN u32_t                    num_kqes);

void
mm_sc_comp_slow_path_request(
    IN struct _lm_device_t *pdev,
    IN lm_iscsi_state_t *iscsi,
    IN lm_iscsi_slow_path_request_t *sp_request);

lm_status_t
mm_sc_complete_init_request(
    IN lm_device_t *pdev,
    IN struct iscsi_kcqe *kcqe
    );

u8_t 
mm_sc_is_omgr_enabled(IN struct _lm_device_t *_pdev);

lm_status_t
mm_sc_complete_update_request(
    IN lm_device_t *pdev,
    IN struct iscsi_kcqe *kcqe
    );

lm_status_t mm_sc_complete_offload_request(
    IN lm_device_t                *pdev,
    IN lm_iscsi_state_t           *iscsi,
    IN lm_status_t                 comp_status
    );

lm_status_t 
mm_fc_complete_init_request(
    IN    lm_device_t               *pdev,
    IN    struct fcoe_kcqe          *kcqe);

lm_status_t 
mm_fc_complete_ofld_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe);

lm_status_t 
mm_fc_complete_enable_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe);

lm_status_t 
mm_fc_complete_disable_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe);

lm_status_t 
mm_fc_complete_destroy_request(
    IN    lm_device_t               *pdev,
    IN    struct fcoe_kcqe          *kcqe);

lm_status_t 
mm_fc_complete_terminate_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe);


lm_status_t 
mm_fc_complete_stat_request(
    IN    lm_device_t               *pdev,
    IN    struct fcoe_kcqe          *kcqe);

#endif /* _MM_L5IF_H */
