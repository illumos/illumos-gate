
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

#include <sys/atomic.h>

// portable integer type of the pointer size for current platform (64/32)
typedef unsigned long mm_int_ptr_t;

typedef kmutex_t mm_spin_lock_t;

/* overrides __FILE_STRIPPED__ usage in mm.h (__BASENAME__ from Makefile) */
#undef __FILE_STRIPPED__
#define __FILE_STRIPPED__ __BASENAME__

#define mm_read_barrier_imp()  membar_consumer()
#define mm_write_barrier_imp() membar_producer()
#define mm_barrier_imp()   \
    do {                   \
        membar_consumer(); \
        membar_producer(); \
    } while(0)

#define mm_atomic_set_imp(_p, _v) \
    atomic_swap_32((volatile uint32_t *)(_p), (uint32_t)(_v))

#define mm_atomic_dec_imp(_p) atomic_dec_32_nv((volatile uint32_t *)(_p))
#define mm_atomic_inc_imp(_p) atomic_inc_32_nv((volatile uint32_t *)(_p))

#define mm_atomic_and_imp(_p, _v) \
    atomic_and_32((volatile uint32_t *)(_p), (uint32_t)(_v))
#define mm_atomic_long_and_imp(_p, _v) \
    atomic_and_ulong((volatile ulong_t *)(_p), (ulong_t)(_v))

#define mm_atomic_or_imp(_p, _v) \
    atomic_or_32((volatile uint32_t *)(_p), (uint32_t)(_v))
#define mm_atomic_long_or_imp(_p, _v) \
    atomic_or_ulong((volatile ulong_t *)(_p), (ulong_t)(_v))

#define mm_atomic_read_imp(_p) \
    atomic_add_32_nv((volatile uint32_t *)(_p), (int32_t)0)
#define mm_atomic_long_read_imp(_p) \
    atomic_add_long_nv((volatile ulong_t *)(_p), (long)0)

#define mm_atomic_cmpxchg_imp(_p, _old_val, _new_val) \
    atomic_cas_32((volatile uint32_t *)(_p), (uint32_t)_old_val, (uint32_t)_new_val)


#if defined(__SunOS_MDB)

/* Solaris debugger (MDB) doesn't have access to ddi_get/put routines */

#define MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL) \
    LM_BAR_WR32_ADDRESS((PDEV), ((u8_t *)PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV),(CID))].cid_resc.mapped_cid_bar_addr + (DPM_TRIGER_TYPE)), (VAL));

#else /* __SunOS && !__SunOS_MDB */

#define MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL) \
    ddi_put32(PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV),(CID))].cid_resc.reg_handle, \
              (uint32_t *)((caddr_t)PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV),(CID))].cid_resc.mapped_cid_bar_addr + (DPM_TRIGER_TYPE)), \
              (VAL))

#endif /* __SunOS_MDB */

#define MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw) \
    mm_register_lpme((_pdev), (_func), (_b_fw_access), (_b_queue_for_fw))


#define MM_DCB_MP_L2_IS_ENABLE(_pdev)  (FALSE)

void MM_ACQUIRE_SPQ_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_SPQ_LOCK_IMP(struct _lm_device_t * pDev);
void MM_ACQUIRE_SPQ_LOCK_DPC_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_SPQ_LOCK_DPC_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_CID_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_CID_LOCK_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_REQUEST_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_REQUEST_LOCK_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_PHY_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_PHY_LOCK_IMP(struct _lm_device_t * pDev);
void MM_ACQUIRE_PHY_LOCK_DPC_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_PHY_LOCK_DPC_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_MCP_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_MCP_LOCK_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t * pDev);
void MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_IND_REG_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_IND_REG_LOCK_IMP(struct _lm_device_t * pDev);

#define MM_ACQUIRE_RAMROD_COMP_LOCK_IMP(pDev)
#define MM_RELEASE_RAMROD_COMP_LOCK_IMP(pDev)

void MM_ACQUIRE_LOADER_LOCK_IMP();
void MM_RELEASE_LOADER_LOCK_IMP();

void MM_ACQUIRE_SP_REQ_MGR_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_SP_REQ_MGR_LOCK_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_SB_LOCK_IMP(struct _lm_device_t * pDev, u8_t sb_idx);
void MM_RELEASE_SB_LOCK_IMP(struct _lm_device_t * pDev, u8_t sb_idx);

void MM_ACQUIRE_ETH_CON_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_ETH_CON_LOCK_IMP(struct _lm_device_t * pDev);

#ifdef VF_INVOLVED

#error "VF_INVOLVED defined with no backend MM implementation"

#define MM_ACQUIRE_PF_LOCK_IMP(pdev)
#define MM_RELEASE_PF_LOCK_IMP(pdev)

#define MM_ACQUIRE_VFS_STATS_LOCK_IMP(pdev)
#define MM_RELEASE_VFS_STATS_LOCK_IMP(pdev)
#define MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(pdev)
#define MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(pdev)

#endif /* VF_INVOLVED */


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

void mm_bar_copy_buffer(struct _lm_device_t * pdev,
                        u8_t                  bar,
                        u32_t                 offset,
                        u32_t                 size,
                        u32_t                 *buf_ptr);

u32_t mm_get_cap_offset(struct _lm_device_t * pdev,
                        u32_t                 cap_id);

u32_t mm_get_wol_flags(struct _lm_device_t * pdev);

u32_t mm_get_feature_flags(struct _lm_device_t * pdev);

u32_t mm_get_vmq_cnt(struct _lm_device_t * pdev);

lm_status_t mm_i2c_update(struct _lm_device_t * pdev);

u64_t mm_query_system_time(void);

