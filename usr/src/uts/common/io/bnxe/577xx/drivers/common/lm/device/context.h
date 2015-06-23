#ifndef __CONTEXT_H
#define __CONTEXT_H
/*
functions for managing Chip per-connection context
*/
#include "lm5710.h"

#define CONN_ID_INVALID                            (0xFFFFFFFF)

#define LM_CONN_MAX_FUNC(_pdev,_conn)             (((_pdev)->context_info->proto_end[_conn]- \
                                                    (_pdev)->context_info->proto_start[_conn]) + 1)

#define LM_CONN_BASE(_pdev,_conn)               ((_pdev)->context_info->proto_start[_conn])

/* returns a pionter to a connections chip context*/
void * lm_get_context(struct _lm_device_t *pdev, u32_t cid);

/* same as above but returns phys address in 64 bit pointer */
u64_t lm_get_context_phys(struct _lm_device_t *pdev, u32_t cid);

/* context pool initializer and release functions */
lm_status_t lm_alloc_context_pool(struct _lm_device_t *pdev);
lm_status_t lm_setup_context_pool(struct _lm_device_t *pdev);
void lm_release_context_pool(struct _lm_device_t *pdev);

typedef struct _lm_4tuple_t {
    u32_t src_ip[4]; /* in host order */
    u32_t dst_ip[4]; /* in host order */
    
    u8_t ip_type;
    #define LM_IP_TYPE_V4   1
    #define LM_IP_TYPE_V6   2

    u16_t dst_port; /* in host order */
    u16_t src_port; /* in host order */
} lm_4tuple_t;

/* allocate a free context by type 
   returns CID or -1 if none are avaliable 
   takes the list spinlock */
lm_status_t lm_allocate_cid(struct _lm_device_t *pdev, u32_t type, void * cookie, s32_t * cid);

/* returns the size of a context */
lm_status_t lm_get_context_size(struct _lm_device_t *pdev, s32_t * context_size);


/** 
 * sets the CDU validation data to be valid for a given cid
 * 
 * @param pdev - the physical device handle
 * @param cid - the context of this cid will be initialized with the cdu validataion data
 * @param invalidate - the cdu-validation data can be set, and it can be invalidated... this parameters
 *                   determines which it is.
 * @return lm_status_t
 */
lm_status_t lm_set_cdu_validation_data(struct _lm_device_t *pdev, s32_t cid, u8_t invalidate);

/* free a context
   takes the list spinlock */
void lm_free_cid(struct _lm_device_t *pdev, u32_t type, u32_t cid, u8_t notify_fw);

/* inserts 4 tuple to SRC mirror hash 
   to be called after lm_allocate_cid and before init offload ramrod
   returns failure if hash is full
   takes the CID lock */
lm_status_t lm_searcher_mirror_hash_insert(struct _lm_device_t *pdev, u32_t cid, lm_4tuple_t *tuple);

/* removes 4 tuple to SRC mirror hash 
   to be called after cfc del ramrod completion and before lm_recycle_cid
   takes the CID lock */
void lm_searcher_mirror_hash_remove(struct _lm_device_t *pdev, u32_t cid);

/* lookup the protocol cookie for a given CID 
   does not take a lock 
   will assert if the CID is not allocated */
void * lm_cid_cookie(struct _lm_device_t *pdev, u32_t type, u32_t cid);

/* lookup the protocol cid_resc for a given CID 
   does not take a lock 
   will DbgBreakIf( if the CID is not allocated */
lm_cid_resc_t * lm_cid_resc(struct _lm_device_t *pdev, u32_t cid);

/* Find the protocol that 'cid' belongs to. */
u8_t lm_map_cid_to_proto(struct _lm_device_t * pdev, u32_t cid);

void lm_init_connection_context(struct _lm_device_t *pdev, u32_t const sw_cid, u8_t sb_id);

void lm_recycle_cid(struct _lm_device_t *pdev, u32_t cid);

lm_status_t lm_set_cid_resc(struct _lm_device_t *pdev, u32_t type, void *cookie, u32_t cid);

lm_status_t lm_free_cid_resc(struct _lm_device_t *pdev, u32_t type, u32_t cid, u8_t notify_fw);

/* lookup the slow path request manager from within
   the protocol cid_resc for a given CID 
   does not take a lock 
   will DbgBreakIf( if the CID is not allocated */
lm_sp_req_manager_t *lm_cid_sp_req_mgr(struct _lm_device_t *pdev, u32_t cid);

typedef enum {
    LM_CID_STATE_VALID,
    LM_CID_STATE_PENDING,
    LM_CID_STATE_ERROR
} lm_cid_state_enum;

lm_cid_state_enum
lm_cid_state(
    IN struct _lm_device_t *pdev, 
    IN u32_t cid
    );

lm_status_t
lm_set_cid_state(
    IN struct _lm_device_t *pdev, 
    IN u32_t cid,
    IN lm_cid_state_enum state
    );


void lm_cid_recycled_cb_register(struct _lm_device_t *pdev, u8_t type, lm_cid_recycled_cb_t cb);

void lm_cid_recycled_cb_deregister(struct _lm_device_t *pdev, u8_t type);

lm_status_t lm_set_con_state(struct _lm_device_t *pdev, u32_t cid, u32_t state);

u32_t lm_get_con_state(struct _lm_device_t *pdev, u32_t cid);

#endif /* __CONTEXT_H */


