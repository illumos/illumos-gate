
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

#include "sync.h"
#include "lm5710.h"

#ifndef UEFI64
typedef u32_t mm_int_ptr_t;
#else
typedef u64_t mm_int_ptr_t;
#endif

typedef int mm_spin_lock_t;

#define mm_read_barrier_imp()
#define mm_write_barrier_imp()
#define mm_barrier_imp()

static __inline void mm_atomic_set_imp(u32_t *p, u32_t v)
{
    LOCK();
    *p = v;
    UNLOCK();
}

static __inline s32_t mm_atomic_dec_imp(u32_t *p)
{
    s32_t ret;
    LOCK();
    ret = --(*p);
    UNLOCK();
    return ret;
}

static __inline s32_t mm_atomic_inc_imp(u32_t *p)
{
    s32_t ret;
    LOCK();
    ret = ++(*p);
    UNLOCK();
    return ret;
}

static __inline s32_t mm_atomic_and_imp(u32_t *p, u32_t v)
{
    s32_t ret;
    LOCK();
    ret = *p;
    *p &= v;
    UNLOCK();
    return ret;
}

static __inline unsigned long mm_atomic_long_and_imp(unsigned long *p,
                                                     unsigned long v)
{
    unsigned long ret;
    LOCK();
    ret = *p;
    *p &= v;
    UNLOCK();
    return ret;
}

static __inline s32_t mm_atomic_or_imp(u32_t *p, u32_t v)
{
    s32_t ret;
    LOCK();
    ret = *p;
    *p |= v;
    UNLOCK();
    return ret;
}

static __inline unsigned long mm_atomic_long_or_imp(unsigned long *p,
                                                    unsigned long v)
{
    unsigned long ret;
    LOCK();
    ret = *p;
    *p |= v;
    UNLOCK();
    return ret;
}

#define mm_atomic_read_imp(_p)      (*_p)
#define mm_atomic_long_read_imp(_p) (*_p)

static __inline s32_t mm_atomic_cmpxchg_imp(u32_t *p,
                                            u32_t old_v,
                                            u32_t new_v)
{
    s32_t ret;
    LOCK();
    ret = *p;
    if (*p == old_v)
    {
        *p = new_v;
    }
    UNLOCK();
    return ret;
}


#define MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL) \
    LM_BAR_WR32_OFFSET((PDEV), BAR_1, (u32_t)((int_ptr_t)((u8_t *)(PDEV)->context_info->array[CID].cid_resc.mapped_cid_bar_addr - \
                                                          (PDEV)->hw_info.mem_base[BAR_1].as_u64 + (DPM_TRIGER_TYPE))), (VAL))

#define MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw) \
    (LM_STATUS_SUCCESS)


#define MM_ACQUIRE_SPQ_LOCK_IMP(pdev)     LOCK()
#define MM_RELEASE_SPQ_LOCK_IMP(pdev)     UNLOCK()
#define MM_ACQUIRE_SPQ_LOCK_DPC_IMP(pdev) LOCK()
#define MM_RELEASE_SPQ_LOCK_DPC_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_CID_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_CID_LOCK_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_REQUEST_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_REQUEST_LOCK_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_PHY_LOCK_IMP(pdev)     LOCK()
#define MM_RELEASE_PHY_LOCK_IMP(pdev)     UNLOCK()
#define MM_ACQUIRE_PHY_LOCK_DPC_IMP(pdev) LOCK()
#define MM_RELEASE_PHY_LOCK_DPC_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_MCP_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_MCP_LOCK_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(pdev)     LOCK()
#define MM_RELEASE_ISLES_CONTROL_LOCK_IMP(pdev)     UNLOCK()
#define MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(pdev) LOCK()
#define MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_IND_REG_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_IND_REG_LOCK_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_RAMROD_COMP_LOCK_IMP(_pdev) LOCK()
#define MM_RELEASE_RAMROD_COMP_LOCK_IMP(_pdev) UNLOCK()

#define MM_ACQUIRE_LOADER_LOCK_IMP() LOCK()
#define MM_RELEASE_LOADER_LOCK_IMP() UNLOCK()

#define MM_ACQUIRE_SP_REQ_MGR_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_SP_REQ_MGR_LOCK_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_SB_LOCK_IMP(pdev, sb_idx) LOCK()
#define MM_RELEASE_SB_LOCK_IMP(pdev, sb_idx) UNLOCK()

#define MM_ACQUIRE_ETH_CON_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_ETH_CON_LOCK_IMP(pdev) UNLOCK()

#ifdef VF_INVOLVED

#define MM_ACQUIRE_PF_LOCK_IMP(pdev) LOCK()
#define MM_RELEASE_PF_LOCK_IMP(pdev) UNLOCK()

#define MM_ACQUIRE_VFS_STATS_LOCK_IMP(pdev)     LOCK()
#define MM_RELEASE_VFS_STATS_LOCK_IMP(pdev)     UNLOCK()
#define MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(pdev) LOCK()
#define MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(pdev) UNLOCK()

#endif /* VF_INVOLVED */

static __inline void mm_init_lock(struct _lm_device_t *_pdev,
                                  mm_spin_lock_t *lock)
{
    /* Do nothing */
}

static __inline lm_status_t mm_acquire_lock(mm_spin_lock_t *spinlock)
{
    LOCK();
    return LM_STATUS_SUCCESS;
}

static __inline lm_status_t mm_release_lock(mm_spin_lock_t *spinlock)
{
    UNLOCK();
    return LM_STATUS_SUCCESS;
}






#define mm_er_initiate_recovery_imp(pdev) \
    (LM_STATUS_FAILURE)

#define mm_register_dpc_imp(_pdev, _func) \
    (LM_STATUS_FAILURE)

#define mm_empty_ramrod_received_imp(pdev, empty_data)      

#define mm_dbus_start_if_enabled_imp(pdev)
#define mm_dbus_stop_if_started_imp(pdev)

#ifdef BIG_ENDIAN
// LE
#define mm_le16_to_cpu_imp(val) SWAP_BYTES16(val)
#define mm_cpu_to_le16_imp(val) SWAP_BYTES16(val)
#define mm_le32_to_cpu_imp(val) SWAP_BYTES32(val)
#define mm_cpu_to_le32_imp(val) SWAP_BYTES32(val)
// BE
#define mm_be32_to_cpu_imp(val) (val)
#define mm_cpu_to_be32_imp(val) (val)
#define mm_be16_to_cpu_imp(val) (val)
#define mm_cpu_to_be16_imp(val) (val)
#else /* LITTLE_ENDIAN */
// LE
#define mm_le16_to_cpu_imp(val) (val)
#define mm_cpu_to_le16_imp(val) (val)
#define mm_le32_to_cpu_imp(val) (val)
#define mm_cpu_to_le32_imp(val) (val)
// BE
#define mm_be32_to_cpu_imp(val) SWAP_BYTES32(val)
#define mm_cpu_to_be32_imp(val) SWAP_BYTES32(val)
#define mm_be16_to_cpu_imp(val) SWAP_BYTES16(val)
#define mm_cpu_to_be16_imp(val) SWAP_BYTES16(val)
#endif /* ifdef BIG_ENDIAN */


#define mm_get_bar_offset_imp(pdev, bar_num, bar_addr) \
    lm_get_bar_offset_direct(pdev, bar_num, bar_addr)

#define mm_get_bar_size_imp(pdev, bar_num, val_p) \
    lm_get_bar_size_direct(pdev, bar_num, val_p)

#define MM_DCB_MP_L2_IS_ENABLE(_pdev)  (FALSE)

void mm_bar_read_byte(struct _lm_device_t *pdev,
                      u8_t bar,
                      u32_t offset,
                      u8_t *ret);

void mm_bar_read_word(struct _lm_device_t *pdev,
                      u8_t bar,
                      u32_t offset,
                      u16_t *ret);

void mm_bar_read_dword(struct _lm_device_t *pdev,
                       u8_t bar,
                       u32_t offset,
                       u32_t *ret);

void mm_bar_read_ddword(struct _lm_device_t *pdev,
                        u8_t bar,
                        u32_t offset,
                        u64_t *ret);

void mm_bar_write_byte(struct _lm_device_t *pdev,
                       u8_t bar,
                       u32_t offset,
                       u8_t val);

void mm_bar_write_word(struct _lm_device_t *pdev,
                       u8_t bar,
                       u32_t offset,
                       u16_t val);

void mm_bar_write_dword(struct _lm_device_t *pdev,
                        u8_t bar,
                        u32_t offset,
                        u32_t val);

void mm_bar_write_ddword(struct _lm_device_t *pdev,
                         u8_t bar,
                         u32_t offset,
                         u64_t val);

void mm_bar_copy_buffer(
	struct _lm_device_t * _pdev,
	u8_t                  bar,
	u32_t                 offset,
    u32_t                 size,
	u32_t                 *buf_ptr
	);

u32_t mm_get_wol_flags( IN struct _lm_device_t* pdev );

u32_t mm_get_feature_flags(struct _lm_device_t* pdev);

u32_t mm_get_vmq_cnt(struct _lm_device_t* pdev);
 
lm_status_t mm_i2c_update(struct _lm_device_t *pdev);

u64_t mm_query_system_time(void); 
