
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

#include <ntddk.h>
#include <ndis.h>

#ifndef __FILE_STRIPPED__
#define __FILE_STRIPPED__  strrchr(__FILE__, '\\')   ?   strrchr(__FILE__, '\\')   + 1 : __FILE__
#endif 

// portable integer type of the pointer size for current platform (64/32)
typedef ULONG_PTR mm_int_ptr_t;

typedef NDIS_SPIN_LOCK mm_spin_lock_t;

#if defined(NDIS31_MINIPORT) || defined(NDIS40_MINIPORT) || defined(NDIS50_MINIPORT)

#define mm_read_barrier_imp()
#define mm_write_barrier_imp()
#define mm_barrier_imp()

#else

#ifdef _IA64_
#define mm_read_barrier_imp()  KeMemoryBarrier()
#else
#define mm_read_barrier_imp()  KeMemoryBarrierWithoutFence()
#endif

#define mm_write_barrier_imp() KeMemoryBarrier()
#define mm_barrier_imp()       KeMemoryBarrier()

#endif

#define mm_atomic_set_imp(_p, _v) InterlockedExchange((long*)(_p), (long)(_v))

#define mm_atomic_dec_imp(_p) InterlockedDecrement((long*)(_p))
#define mm_atomic_inc_imp(_p) InterlockedIncrement((long*)(_p))

#define mm_atomic_and_imp(_p, _v)      InterlockedAnd((long*)(_p), (long)(_v))
#define mm_atomic_long_and_imp(_p, _v) mm_atomic_and_imp((_p), (_v))

#define mm_atomic_or_imp(_p, _v)      InterlockedOr((long*)(_p), (long)(_v) )
#define mm_atomic_long_or_imp(_p, _v) mm_atomic_or_imp((_p), (_v))

#define mm_atomic_read_imp(_p) \
    InterlockedExchangeAdd((long*)(_p), (long)(0))
#define mm_atomic_long_read_imp(_p) mm_atomic_read_imp((_p))

#define mm_atomic_cmpxchg_imp(_p, _old_val, _new_val) \
    InterlockedCompareExchange(_p, (long)_new_val, (long)_old_val )


#define MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL) \
    LM_BAR_WR32_ADDRESS((PDEV), ((u8_t *)PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV),(CID))].cid_resc.mapped_cid_bar_addr + (DPM_TRIGER_TYPE)), (VAL))

#define MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw) \
    mm_register_lpme((_pdev), (_func), (_b_fw_access), (_b_queue_for_fw))

u32_t
mm_dcb_mp_l2_is_enable(struct _lm_device_t	*pdev);
#define MM_DCB_MP_L2_IS_ENABLE(_pdev)  (mm_dcb_mp_l2_is_enable(pdev))

void MM_ACQUIRE_SPQ_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_SPQ_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_SPQ_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_SPQ_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_CID_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_CID_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_REQUEST_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_REQUEST_LOCK_IMP(struct _lm_device_t *_pdev);

#define MM_ACQUIRE_REQUEST_LOCK_DPC_IMP(pdev)
#define MM_RELEASE_REQUEST_LOCK_DPC_IMP(pdev)

void MM_ACQUIRE_PHY_LOCK_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_PHY_LOCK_IMP(struct _lm_device_t * pDev);
void MM_ACQUIRE_PHY_LOCK_DPC_IMP(struct _lm_device_t * pDev);
void MM_RELEASE_PHY_LOCK_DPC_IMP(struct _lm_device_t * pDev);

void MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

#define MM_ACQUIRE_RAMROD_COMP_LOCK_IMP(_pdev)
#define MM_RELEASE_RAMROD_COMP_LOCK_IMP(_pdev)

void MM_ACQUIRE_MCP_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_MCP_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ISLES_CONTROL_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_IND_REG_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_IND_REG_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_LOADER_LOCK_IMP();
void MM_RELEASE_LOADER_LOCK_IMP();

void MM_ACQUIRE_SP_REQ_MGR_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_SP_REQ_MGR_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_SB_LOCK_IMP(struct _lm_device_t *_pdev, u8_t _sb_idx);
void MM_RELEASE_SB_LOCK_IMP(struct _lm_device_t *_pdev, u8_t _sb_idx);

void MM_ACQUIRE_ETH_CON_LOCK(struct _lm_device_t *_pdev);
void MM_RELEASE_ETH_CON_LOCK(struct _lm_device_t *_pdev);

#ifdef VF_INVOLVED

void MM_ACQUIRE_PF_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_PF_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_VFS_STATS_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_VFS_STATS_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

#endif /* VF_INVOLVED */

#define mm_er_initiate_recovery_imp(pdev) \
    (LM_STATUS_FAILURE)

#define mm_register_dpc_imp(_pdev, _func) \
    (LM_STATUS_FAILURE)

void mm_empty_ramrod_received_imp(struct _lm_device_t *pdev, 
                                  const u32_t empty_data);

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

