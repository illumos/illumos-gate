
/*****************************************************************************
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *****************************************************************************/

#if defined(USER_LINUX)
typedef int mm_spin_lock_t;

#else

#include "ediag_compat.h"

// portable integer type of the pointer size for current platform (64/32)
typedef unsigned long mm_int_ptr_t;

typedef struct semaphore_t * mm_spin_lock_t;


#define mm_read_barrier_imp() \
    do {                      \
        barrier();            \
        ediag_rmb();          \
    } while(0)

#define mm_write_barrier_imp() \
    do {                       \
        barrier();             \
        ediag_wmb();           \
    } while(0)

#define mm_barrier_imp() \
    do {                 \
        barrier();       \
        ediag_rmb();     \
        ediag_wmb();     \
    } while(0)

#define mm_atomic_set_imp(_p, _v) ediag_atomic_set((s32_t *)_p, (s32_t)_v)

#define mm_atomic_dec_imp(_p) ediag_atomic_dec_and_test((s32_t *)_p)

/* returns the decremented value */
#define mm_atomic_inc_imp(_p) ediag_atomic_inc_and_test((s32_t *)_p)

#define mm_atomic_read_imp(_p) ediag_atomic_read((s32_t *)_p)

#define mm_atomic_long_read_imp(_p) ediag_atomic_long_read((unsigned long *)_p)

#define mm_atomic_cmpxchg_imp(_p, _cmp, _new_v) ediag_atomic_cmpxchg((s32_t *)_p, (int)_cmp, (int)_new_v)


#define mm_atomic_and_imp(p, v) \
do {                            \
    *(p) = *(p) & (v);          \
} while (0)

#define mm_atomic_long_and_imp(p, v) mm_atomic_and((p), (v))

#define mm_atomic_or_imp(p, v) \
do {                           \
    *(p) = *(p) | (v);         \
} while (0)

#define mm_atomic_long_or_imp(p, v) mm_atomic_or((p), (v))


#define MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL) \
    LM_BAR_WR32_ADDRESS((PDEV), ((u8_t *)PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV),(CID))].cid_resc.mapped_cid_bar_addr + (DPM_TRIGER_TYPE)), (VAL))

#define MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw) \
    (LM_STATUS_SUCCESS)

#define MM_DCB_MP_L2_IS_ENABLE(_pdev)  (FALSE)

void MM_ACQUIRE_SPQ_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_SPQ_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_SPQ_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_SPQ_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_CID_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_CID_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_REQUEST_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_REQUEST_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_REQUEST_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_REQUEST_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_PHY_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_PHY_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_PHY_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_PHY_LOCK_DPC_IMP(struct _lm_device_t *_pdev);


void MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_RAMROD_COMP_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_RAMROD_COMP_LOCK_IMP(struct _lm_device_t *_pdev);




#define MM_ACQUIRE_IND_REG_LOCK_IMP(pdev)
#define MM_RELEASE_IND_REG_LOCK_IMP(pdev)

void MM_ACQUIRE_LOADER_LOCK_IMP(void);
void MM_RELEASE_LOADER_LOCK_IMP(void);

void MM_ACQUIRE_SP_REQ_MGR_LOCK_IMP(struct _lm_device_t *pdev);
void MM_RELEASE_SP_REQ_MGR_LOCK_IMP(struct _lm_device_t *pdev);

void MM_ACQUIRE_MCP_LOCK_IMP(struct _lm_device_t *pdev);
void MM_RELEASE_MCP_LOCK_IMP(struct _lm_device_t *pdev);

void MM_ACQUIRE_SB_LOCK_IMP(struct _lm_device_t *_pdev, u8_t _sb_idx);
void MM_RELEASE_SB_LOCK_IMP(struct _lm_device_t *_pdev, u8_t _sb_idx);

void MM_ACQUIRE_ETH_CON_LOCK_IMP(struct _lm_device_t *pdev);
void MM_RELEASE_ETH_CON_LOCK_IMP(struct _lm_device_t *pdev);

#ifdef VF_INVOLVED

void MM_ACQUIRE_PF_LOCK_IMP(struct _lm_device_t *pdev);
void MM_RELEASE_PF_LOCK_IMP(struct _lm_device_t *pdev);

void MM_ACQUIRE_VFS_STATS_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_VFS_STATS_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

#endif /* VF_INVOLVED */


#define mm_er_initiate_recovery_imp(pdev) \
    (LM_STATUS_FAILURE)

#define mm_register_dpc_imp(_pdev, _func) \
    (LM_STATUS_FAILURE)

#define mm_empty_ramrod_received_imp(pdev, empty_data)        

#define mm_dbus_start_if_enabled_imp(_pdev)
#define mm_dbus_stop_if_started_imp(_pdev)


lm_status_t mm_get_bar_offset_imp(struct _lm_device_t *pdev,
                                   u8_t barn,
                                   lm_address_t *bar_addr);

lm_status_t mm_get_bar_size_imp(struct _lm_device_t *pdev,
                                 u8_t bar_num,
                                 u32_t *bar_sz);



lm_status_t mm_get_bar_size(
	struct _lm_device_t  * pdev,
    u8_t                   bar_num,
	u32_t                * bar_sz
	);

void mm_bar_read_byte(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u8_t                * ret
	);


void mm_bar_read_word(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u16_t               * ret
	);

void mm_bar_read_dword(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u32_t               * ret
	);


void mm_bar_read_ddword(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u64_t               * ret
	);


void mm_bar_write_byte(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u8_t                  val
	);


void mm_bar_write_word(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u16_t                 val
	);


void mm_bar_write_dword(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u32_t                 val
	);


void mm_io_write_dword(
	struct _lm_device_t * _pdev,
	void                * addr,
	u32_t                 val
	);


void mm_bar_write_ddword(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
	u64_t                 val
	);


void mm_bar_copy_buffer(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
    u32_t                 size,
	u32_t                 *buf_ptr
	);



static inline u16_t mm_le16_to_cpu_imp(u16_t val)
{
	return ediag_le16_to_cpu(val);
}

static inline u32_t mm_le32_to_cpu_imp(u32_t val)
{
	return ediag_le32_to_cpu(val);
}

static inline u32_t mm_be32_to_cpu_imp(u32_t val)
{
	return ediag_be32_to_cpu(val);
}

static inline u32_t mm_be16_to_cpu_imp(u32_t val)
{
    return ediag_be16_to_cpu(val);
}

static inline u32_t mm_cpu_to_be32_imp(u32_t val)
{
    return ediag_cpu_to_be32(val);
}

static inline u32_t mm_cpu_to_be16_imp(u32_t val)
{
    return ediag_cpu_to_be16(val);
}

static inline u16_t mm_cpu_to_le16_imp(u16_t val)
{
	return ediag_cpu_to_le16(val);
}

static inline u32_t mm_cpu_to_le32_imp(u32_t val)
{
	return ediag_cpu_to_le32(val);
}

u32_t mm_get_wol_flags( IN struct _lm_device_t* pdev );

u32_t mm_get_feature_flags(struct _lm_device_t* pdev);

u32_t mm_get_vmq_cnt(struct _lm_device_t* pdev);

lm_status_t mm_i2c_update(struct _lm_device_t *pdev);

u64_t mm_query_system_time(void);

/* the following are __LINUX only... */

u32_t mm_get_cap_offset(struct _lm_device_t *pdev, 
                        u32_t cap_id);

void mm_eth_ramrod_comp_cb(struct _lm_device_t *pdev,
                           struct common_ramrod_eth_rx_cqe *cqe);

void mm_common_ramrod_comp_cb(struct _lm_device_t *pdev,
                              struct event_ring_msg *msg);


#endif
