
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

#if defined(_VBD_)
#include <ntddk.h>
#elif defined(_VBD_CMD_)
#include "vc_os_emul.h"
#endif

#include "../../Windows/b10bdrv/um_lock.h"

// portable integer type of the pointer size for current platform (64/32)
typedef ULONG_PTR mm_int_ptr_t;

typedef spin_lock_t mm_spin_lock_t;

#if defined(_IA64_) || defined(_VBD_CMD_)
#define mm_read_barrier_imp()  KeMemoryBarrier()
#else
#define mm_read_barrier_imp()  KeMemoryBarrierWithoutFence()
#endif

/* Sections that are different between VBD_CMD and VBD (shouldn't be alot...)  */
#if defined(_VBD_)
lm_status_t mm_get_bar_offset_imp(struct _lm_device_t *pdev,
                                  u8_t barn,
                                  lm_address_t *bar_addr);

lm_status_t mm_get_bar_size_imp(struct _lm_device_t *pdev,
                                 u8_t bar_num,
                                 u32_t *bar_sz);

#else

#define mm_get_bar_offset_imp(pdev, bar_num, bar_addr) \
    lm_get_bar_offset_direct(pdev, bar_num, bar_addr)

#define mm_get_bar_size_imp(pdev, bar_num, val_p) \
    lm_get_bar_size_direct(pdev, bar_num, val_p)


#endif

#define mm_write_barrier_imp() KeMemoryBarrier()
#define mm_barrier_imp()       KeMemoryBarrier()

#define mm_atomic_set_imp(_p, _v) InterlockedExchange((long*)(_p), (long)(_v))

#define mm_atomic_dec_imp(_p) InterlockedDecrement((long*)(_p))
#define mm_atomic_inc_imp(_p) InterlockedIncrement((long*)(_p))

#define mm_atomic_add_imp(_p, _v) \
    InterlockedExchangeAdd((long*)(_p), (long)(_v))
#define mm_atomic_sub_imp(_p, _v) \
    InterlockedExchangeAdd((long*)(_p), -1*(long)(_v))

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
    if (IS_PFDEV(pdev)) \
    { \
        LM_BAR_WR32_ADDRESS((PDEV), ((u8_t *)PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV), (CID))].cid_resc.mapped_cid_bar_addr + (DPM_TRIGER_TYPE)), (VAL)); \
    } \
    else \
    { \
        LM_BAR_WR32_ADDRESS((PDEV), ((u8_t *)(PDEV)->context_info->array[VF_TO_PF_CID((PDEV), (CID))].cid_resc.mapped_cid_bar_addr), (VAL)); \
    }

#define MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw) \
    mm_register_lpme((_pdev), (_func), (_b_fw_access), (_b_queue_for_fw))


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

void MM_ACQUIRE_ETH_CON_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_ETH_CON_LOCK_IMP(struct _lm_device_t *_pdev);

#ifdef VF_INVOLVED

void MM_ACQUIRE_PF_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_PF_LOCK_IMP(struct _lm_device_t *_pdev);

void MM_ACQUIRE_VFS_STATS_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_VFS_STATS_LOCK_IMP(struct _lm_device_t *_pdev);
void MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(struct _lm_device_t *_pdev);
void MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(struct _lm_device_t *_pdev);

void
mm_sriov_invalidate_vf_block(
    struct _lm_device_t *pdev,
    u16_t       vf_id,
    u64_t       invalidate_bock);

#endif /* VF_INVOLVED */


lm_status_t mm_er_initiate_recovery_imp(struct _lm_device_t * pdev);

typedef void lm_generic_dpc_func(struct _lm_device_t *pdev);
lm_status_t mm_register_dpc_imp(struct _lm_device_t *_pdev,
                                lm_generic_dpc_func *func);

void mm_empty_ramrod_received_imp(struct _lm_device_t *_pdev,
                                  const u32_t empty_data);

void mm_dbus_start_if_enabled_imp(struct _lm_device_t *_pdev);
void mm_dbus_stop_if_started_imp(struct _lm_device_t *_pdev);


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

u32_t mm_get_cpu_count();


#define RESOURCE_TRACE_FLAG_COUNTERS 0x01
#define RESOURCE_TRACE_FLAG_DESC     0x02
#define RESOURCE_TRACE_FLAG_MDL      0x04 // Currently - not working well!!!

#define MEM_TRACE_FLAG_HIGH          (RESOURCE_TRACE_FLAG_COUNTERS | RESOURCE_TRACE_FLAG_DESC)
#define MEM_TRACE_FLAG_DEFAULT       RESOURCE_TRACE_FLAG_COUNTERS

#define RESOURCE_TRACE_INC(_pdev, _cli_idx, _type, _field)             \
{                                                                      \
    DbgBreakIf((_cli_idx) >= MAX_DO_TYPE_CNT);                         \
    DbgBreakIf((_type) >= RESOURCE_TYPE_MAX);                          \
    InterlockedIncrement((long*)&_pdev->resource_list.                 \
                                   type_counters_arr[_cli_idx][_type]. \
                                     _field);                          \
}

#define RESOURCE_TRACE_DEC(_pdev, _cli_idx, _type, _field)             \
{                                                                      \
    DbgBreakIf((_cli_idx) >= MAX_DO_TYPE_CNT);                         \
    DbgBreakIf((_type) >= RESOURCE_TYPE_MAX);                          \
    InterlockedDecrement((long*)&_pdev->resource_list.                 \
                                   type_counters_arr[_cli_idx][_type]. \
                                     _field);                          \
}

#define RESOURCE_TRACE_ADD(_pdev, _cli_idx, _type, _field, _size)         \
{                                                                         \
    DbgBreakIf((_cli_idx) >= MAX_DO_TYPE_CNT);                            \
    DbgBreakIf((_type) >= RESOURCE_TYPE_MAX);                             \
    InterlockedExchangeAdd((long*)&(_pdev->resource_list.                 \
                                      type_counters_arr[_cli_idx][_type]. \
                                        _field), (long)(_size));          \
}

#define RESOURCE_TRACE_SUB(_pdev, _cli_idx, _type, _field, _size) \
    RESOURCE_TRACE_ADD( _pdev, _cli_idx, _type, _field, 0L-(long)_size)

#define RESOURCE_TRACE_UPDATE_PEAK(_pdev, _cli_idx, _type)                  \
{                                                                           \
    DbgBreakIf((_cli_idx) >= MAX_DO_TYPE_CNT);                              \
    DbgBreakIf((_type) >= RESOURCE_TYPE_MAX);                               \
    if (_pdev->resource_list.type_counters_arr[_cli_idx][_type].size >      \
        _pdev->resource_list.type_counters_arr[_cli_idx][_type].size_peak)  \
    {                                                                       \
        _pdev->resource_list.type_counters_arr[_cli_idx][_type].size_peak = \
            _pdev->resource_list.type_counters_arr[_cli_idx][_type].size;   \
    }                                                                       \
    if (_pdev->resource_list.type_counters_arr[_cli_idx][_type].cnt >       \
        _pdev->resource_list.type_counters_arr[_cli_idx][_type].cnt_peak)   \
    {                                                                       \
        _pdev->resource_list.type_counters_arr[_cli_idx][_type].cnt_peak =  \
            _pdev->resource_list.type_counters_arr[_cli_idx][_type].cnt;    \
    }                                                                       \
}


/* this is _NTDDK_ only... */
u32_t mm_get_wol_flags(struct _lm_device_t* pdev);

/* this is _NTDDK_ only... */
u32_t mm_get_vmq_cnt(struct _lm_device_t* pdev);

/* this is _NTDDK_ only... */
u32_t mm_get_feature_flags(struct _lm_device_t* pdev);

u32_t mm_get_cap_offset(struct _lm_device_t *pdev, u32_t cap_id);


void mm_dcb_indicate_event(
    IN struct _lm_device_t  *pdev,    
    IN lm_event_code_t      event,
    IN u8_t                 *event_buf,
    IN u32_t                event_buf_size  
    );
#define MM_DCB_INDICATE_EVENT(_pdev,_event,_event_buf, _event_buf_size)     mm_dcb_indicate_event(_pdev,_event,_event_buf, _event_buf_size)

u32_t
mm_dcb_mp_l2_is_enable(struct _lm_device_t	*pdev);
#define MM_DCB_MP_L2_IS_ENABLE(_pdev)  (mm_dcb_mp_l2_is_enable(pdev))

