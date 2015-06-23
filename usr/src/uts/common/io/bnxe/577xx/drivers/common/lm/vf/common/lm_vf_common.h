#ifndef _LM_VF_COMMON_H
#define _LM_VF_COMMON_H

#include "lm_defs.h"
#define ELEM_OF_RES_ARRAY_SIZE_IN_BYTES     (sizeof(u32_t))
#define ELEM_OF_RES_ARRAY_SIZE_IN_BITS      (ELEM_OF_RES_ARRAY_SIZE_IN_BYTES*8)

/* VF functions*/

/* Description:
*/
u8_t lm_vf_is_function_after_flr(struct _lm_device_t * pdev);

lm_status_t lm_vf_setup_alloc_resc(struct _lm_device_t *pdev, u8_t b_is_alloc);

lm_status_t lm_vf_allocate_resc_in_pf(struct _lm_device_t *pdev);

lm_status_t
lm_vf_init_dev_info(struct _lm_device_t *pdev);

lm_status_t
lm_vf_chip_init(struct _lm_device_t *pdev);

lm_status_t
lm_vf_chip_reset(struct _lm_device_t *pdev, lm_reason_t reason);

lm_status_t
lm_vf_recycle_resc_in_pf(struct _lm_device_t *pdev);

lm_status_t 
lm_vf_get_intr_blk_info(struct _lm_device_t *pdev);

lm_status_t 
lm_vf_get_bar_offset(struct _lm_device_t *pdev, u8_t bar_num, lm_address_t * bar_addr);

lm_status_t 
lm_vf_get_vf_id(struct _lm_device_t * pdev);

lm_status_t
lm_vf_en(struct _lm_device_t * pf_dev, u16_t vf_num);

lm_status_t
lm_vf_dis(struct _lm_device_t * pf_dev);

lm_status_t
lm_vf_prep(struct _lm_device_t * pf_dev, struct _lm_device_t * vf_dev);


lm_status_t
lm_vf_get_pcicfg_info(struct _lm_device_t * pdev);

lm_status_t
lm_vf_enable_vf(struct _lm_device_t *pdev);

lm_status_t
lm_vf_enable_igu_int(struct _lm_device_t * pdev);

lm_status_t
lm_vf_disable_igu_int(struct _lm_device_t * pdev);

void lm_pf_fl_vf_reset_set_inprogress(struct _lm_device_t * pdev, u8_t abs_vf_id);
void lm_pf_fl_vf_reset_clear_inprogress(struct _lm_device_t *pdev, u8_t abs_vf_id);
u8_t lm_pf_fl_vf_reset_is_inprogress(struct _lm_device_t *pdev, u8_t abs_vf_id);

/*=================================CHANNEL_VF===========================================*/
#define LM_FW_VF_SB_ID(_vf_info, _sb_id) ((_vf_info)->vf_chains[(_sb_id)].fw_ndsb)
#define LM_SW_VF_SB_ID(_vf_info, _sb_id) ((_vf_info)->vf_chains[(_sb_id)].sw_ndsb)

#define LM_FW_VF_QZONE_ID(_vf_info, _q_zone_id) ((_vf_info)->vf_chains[(_q_zone_id)].fw_qzone_id)
#define LM_FW_VF_DHC_QZONE_ID(_vf_info, _q_zone_id)  ((_vf_info)->vf_chains[(_q_zone_id)].fw_qzone_id)

#define LM_VF_IGU_SB_ID(_vf_info, _igu_sb_id) ((_vf_info)->vf_chains[(_igu_sb_id)].igu_sb_id)

#define LM_FW_VF_STATS_CNT_ID(_vf_info) ((_vf_info)->base_fw_stats_id)

#define LM_FW_VF_CLI_ID(_vf_info, _q_id)  ((_vf_info)->vf_chains[(_q_id)].fw_client_id)
#define LM_SW_VF_CLI_ID(_vf_info, _q_id)  ((_vf_info)->vf_chains[(_q_id)].sw_client_id)

#define LM_VF_Q_ID_TO_PF_CID(_pdev,_vf_info, _q_id) ((((1 << LM_VF_MAX_RVFID_SIZE) | (_vf_info)->abs_vf_id) <<  LM_VF_CID_WND_SIZE(_pdev)) | (_q_id))

typedef struct _lm_pf_vf_response_t
{
    u32_t           state;
#define PF_VF_RESPONSE_FLAG_OFFSET     16
    u16_t           recent_opcode;
    u16_t           req_resp_state;
#define VF_PF_UNKNOWN_STATE                     0
#define VF_PF_WAIT_FOR_START_REQUEST            1
#define VF_PF_WAIT_FOR_NEXT_CHUNK_OF_REQUEST    2
#define VF_PF_REQUEST_IN_PROCESSING             3
#define VF_PF_RESPONSE_READY                    4

    u32_t           request_size;
    u32_t           request_offset;
    void *          request_virt_addr;
    lm_address_t    request_phys_addr;
    u32_t           response_size;
    u32_t           response_offset;
    void *          response_virt_addr;
    lm_address_t    response_phys_addr;
    lm_address_t    vf_pf_message_addr;
}
    lm_pf_vf_response_t;

typedef struct _lm_vf_location_t
{
    u16_t   pci_segment_num;
    u8_t    pci_bus_num;
    u8_t    pci_device_num;
    u8_t    pci_function_num;
    u8_t    pad[3];
}
    lm_vf_location_t;

typedef struct _lm_vf_stats_t
{
    struct per_queue_stats *pf_fw_stats_virt_data;
    lm_address_t	        pf_fw_stats_phys_data;
    lm_address_t	        vf_fw_stats_phys_data;
    void   *mirror_stats_fw;

    u32_t                   vf_stats_state;
#define VF_STATS_NONE               0
#define VF_STATS_REQ_SUBMITTED      1
#define VF_STATS_REQ_IN_PROCESSING  2
#define VF_STATS_REQ_READY          3

    u8_t                    vf_stats_flag;
#define VF_STATS_COLLECT_FW_STATS_FOR_PF   0x01
#define VF_STATS_COLLECT_FW_STATS_FOR_VF   0x02

    u8_t                    stop_collect_stats;
    u8_t                    do_not_collect_pf_stats;
    u8_t                    pad;
    u32_t                   vf_stats_cnt;
    u32_t                   vf_exracted_stats_cnt;
}
    lm_vf_stats_t;


typedef struct _lm_vf_slowpath_data_t 
{
    struct eth_rss_update_ramrod_data * rss_rdata;
    lm_address_t rss_rdata_phys;
} 
lm_vf_slowpath_data_t ;

typedef struct _lm_vf_slowpath_info_t {
    lm_vf_slowpath_data_t slowpath_data;

    #define LM_VF_SLOWPATH(vf_info, var)		(vf_info->vf_slowpath_info.slowpath_data.var)
    #define LM_VF_SLOWPATH_PHYS(vf_info, var) (vf_info->vf_slowpath_info.slowpath_data.var##_phys)

    struct ecore_rss_config_obj rss_conf_obj;
    volatile u32_t  sp_rss_state; 
    struct ecore_config_rss_params rss_params;
} lm_vf_slowpath_info_t;


typedef struct _lm_vf_chain_info_t
{
    u8_t    sw_client_id;
    u8_t    fw_client_id;
    u8_t    fw_qzone_id;
    u8_t    sw_ndsb;
    u8_t    fw_ndsb;
    u8_t    igu_sb_id;
    u16_t   mtu;
    u64     sge_addr;
    struct tpa_update_ramrod_data*  
            tpa_ramrod_data_virt;
    lm_address_t                    
            tpa_ramrod_data_phys;
}
    lm_vf_chain_info_t;

typedef struct _lm_vf_tpa_info_t
{
    volatile u32_t  ramrod_recv_cnt;    // Number of ramrods received.Decrement by using Interlockeddecrement.
    u8_t            ipvx_enabled_required;
    u8_t            ipvx_enabled_current;
}
    lm_vf_tpa_info_t ;

typedef struct _lm_vf_info_t
{
    u8_t    relative_vf_id;
    u8_t    abs_vf_id;
    u8_t    vport_state;
#define VF_VPORT_STATE_DELETED              0
#define VF_VPORT_STATE_CREATED              1
#define VF_VPORT_STATE_RESET                2
#define VF_VPORT_STATE_REJECTED             3

    u8_t    vf_si_state;
#define PF_SI_WAIT_FOR_ACQUIRING_REQUEST    0
#define PF_SI_ACQUIRED                      1
#define PF_SI_VF_INITIALIZED                2

    u8_t    base_fw_stats_id;
    u8_t    vport_instance;
    u8_t    num_rxqs;
    u8_t    num_txqs;

    u8_t    num_vport_chains_requested;     /* Requested via Hyper-V manager, VMNetworkAdapter setting*/
    u8_t    num_vf_chains_requested;        /* Requested via VF/PF channel, VF acquiring */
    u8_t    num_igu_sb_available;        
    u8_t    num_allocated_chains;

    u8_t    num_sbs;
    
    u8_t    num_mac_filters;
    u8_t    num_vlan_filters;
    u8_t    num_mc_filters;

    u8_t    is_mac_set;
    u8_t    was_flred;
    u8_t    was_malicious;

    u8_t    is_promiscuous_mode_restricted;

    u16_t    current_interrupr_moderation;
#define VPORT_INT_MOD_UNDEFINED     0
#define VPORT_INT_MOD_ADAPTIVE      1
#define VPORT_INT_MOD_OFF           2
#define VPORT_INT_MOD_LOW           100
#define VPORT_INT_MOD_MEDIUM        200
#define VPORT_INT_MOD_HIGH          300
    
    u8_t    malicious_cnt;
    u8_t    fp_hsi_ver;
    
    u32_t   vf_si_num_of_active_q;
    u32_t   base_cam_offset;

    lm_vf_chain_info_t      vf_chains[16];
    lm_vf_location_t        vf_location;                    
    lm_pf_vf_response_t     pf_vf_response;
    lm_vf_stats_t           vf_stats;
    lm_vf_slowpath_info_t   vf_slowpath_info;
    lm_vf_tpa_info_t        vf_tpa_info;
    void *  um_ctx;
}
    lm_vf_info_t;

typedef struct _lm_vfs_set_t
{
    lm_vf_info_t  * vfs_array;
    u16_t           number_of_enabled_vfs;
    u8_t            vf_sb_cnt;
    u8_t            pad;

    void *          req_resp_virt_addr;
    lm_address_t    req_resp_phys_addr;
    u32_t           req_resp_size;

    void *          pf_fw_stats_set_virt_data;
    lm_address_t	pf_fw_stats_set_phys_data;
    u32_t			pf_fw_stats_set_data_sz;

    u8_t *          mirror_stats_fw_set;

    void *          rss_update_virt_addr;
    lm_address_t    rss_update_phys_addr;
    u32_t           rss_update_size;
} 
    lm_vfs_set_t;

u16_t lm_vf_pf_get_sb_running_index(struct _lm_device_t *pdev, u8_t sb_id, u8_t sm_idx);
u16_t lm_vf_pf_get_sb_index(struct _lm_device_t *pdev, u8_t sb_id, u8_t idx);
u16_t lm_vf_get_doorbell_size(struct _lm_device_t *pdev);

#define RX_Q_VALIDATE   0x01
#define TX_Q_VALIDATE   0x02

typedef enum {
    Q_FILTER_MAC,
    Q_FILTER_VLAN,
    Q_FILTER_MC,
    Q_FILTER_RX_MASK
} q_filter_type;

typedef enum {
    PFVF_BB_CHANNEL_IS_NOT_ACTIVE,
    PFVF_BB_CHANNEL_CRC_ERR,
    PFVF_BB_NO_UPDATE,
    PFVF_BB_VALID_MAC,
} pfvf_bb_event_type;


u8_t lm_vf_is_lamac_restricted(struct _lm_device_t *pdev);
lm_status_t lm_pf_process_standard_request(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);
lm_status_t lm_pf_notify_standard_request_ready(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t * set_done);

lm_status_t lm_vf_pf_acquire_msg(struct _lm_device_t * pdev);
lm_status_t lm_vf_pf_init_vf(struct _lm_device_t * pdev);
lm_status_t lm_vf_pf_setup_q(struct _lm_device_t * pdev, u8 vf_qid, u8_t validation_flag);
lm_status_t lm_vf_pf_tear_q_down(struct _lm_device_t * pdev, u8 vf_qid);
lm_status_t lm_vf_pf_set_q_filters(struct _lm_device_t * pdev, u8 vf_qid, void * cookie, 
                                   q_filter_type filter_type, u8_t * pbuf, u32_t buf_len, 
                                   u16_t vlan_tag, u8_t set_mac);
lm_status_t lm_vf_pf_set_q_filters_list(struct _lm_device_t * pdev, u8 vf_qid, void * cookie,
                                        q_filter_type filter_type, d_list_t * pbuf, 
                                        u16_t vlan_tag, u8_t set_mac);
lm_status_t lm_vf_pf_close_vf(struct _lm_device_t * pdev);
lm_status_t lm_vf_pf_release_vf(struct _lm_device_t * pdev);
lm_status_t lm_vf_pf_update_rss(struct _lm_device_t *pdev, void * cookie, u32_t rss_flags, u8_t rss_result_mask, u8_t * ind_table, u32_t * rss_key);
lm_status_t lm_vf_pf_update_rsc(struct _lm_device_t *pdev);

lm_status_t lm_vf_pf_wait_no_messages_pending(struct _lm_device_t * pdev);

lm_status_t lm_vf_queue_init(struct _lm_device_t *pdev, u8_t cid);
lm_status_t lm_vf_queue_close(struct _lm_device_t *pdev, u8_t cid);
pfvf_bb_event_type lm_vf_check_hw_back_channel(struct _lm_device_t * pdev);

void lm_pf_init_vf_client(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t q_id);
void lm_pf_init_vf_slow_path(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);

lm_status_t lm_pf_init_vf_client_init_data(struct _lm_device_t *pf_dev, lm_vf_info_t *vf_info, u8_t q_id,
                                           struct sw_vf_pf_rxq_params * rxq_params,
                                           struct sw_vf_pf_txq_params * txq_params); 
lm_status_t lm_pf_init_vf_non_def_sb(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t sb_idx, u64 sb_addr); 
lm_status_t lm_pf_enable_vf_igu_int(struct _lm_device_t * pdev, u8_t abs_vf_id);

lm_status_t lm_pf_disable_vf_igu_int(struct _lm_device_t * pdev,  u8_t abs_vf_id);

lm_status_t lm_pf_enable_vf(struct _lm_device_t *pdev,   u8_t abs_vf_id);
lm_status_t lm_pf_vf_wait_for_stats_ready(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);
//struct _lm_vf_pf_message_t * lm_vf_pf_channel_get_message_to_send(struct _lm_device_t * pdev, u8  opcode);
//lm_status_t lm_vf_pf_channel_send(struct _lm_device_t * pdev, struct _lm_vf_pf_message_t * mess); 
//lm_status_t lm_vf_pf_channel_wait_response(struct _lm_device_t * pdev, struct _lm_vf_pf_message_t * mess);

/*
static __inline void * lm_vf_pf_channel_get_message(struct _lm_device_t * pdev)
{
    return pdev->vars.vf_pf_mess.message_virt_addr;
}
*/

u8_t lm_vf_get_free_resource(u32_t * resource, u8_t min_num, u8_t max_num, u8_t num);
void lm_vf_acquire_resource(u32_t * presource, u8_t base_value, u8_t num);
u8_t lm_vf_get_resource_value(u32_t * presource, u8_t base_value);
void lm_vf_release_resource(u32_t * presource, u8_t base_value, u8_t num);
lm_status_t lm_wait_vf_config_rss_done(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);


lm_status_t lm_pf_create_vf(struct _lm_device_t *pdev, u16_t rel_vf_id, void* ctx);
lm_status_t lm_pf_remove_vf(struct _lm_device_t *pdev, u16_t rel_vf_id);
lm_status_t lm_pf_cleanup_vf_after_flr(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);
lm_status_t lm_pf_finally_release_vf(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);
lm_status_t lm_pf_tpa_send_vf_ramrod(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u32_t q_idx, u8_t update_ipv4, u8_t update_ipv6);

u8_t lm_is_vf_rsc_supported(struct _lm_device_t *pdev);

void lm_pf_init_vf_filters(struct _lm_device_t *pdev, lm_vf_info_t *vf_info);
void lm_pf_allow_vf_promiscuous_mode(lm_vf_info_t *vf_info, u8_t is_allowed);
void lm_pf_int_vf_igu_sb_cleanup(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t vf_chain_id);
#endif
/* */
