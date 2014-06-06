
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

#include <minmax.h>

// portable integer type of the pointer size for current platform (64/32)
typedef u64_t mm_int_ptr_t;

typedef int mm_spin_lock_t;

#define mm_read_barrier_imp()
#define mm_write_barrier_imp()
#define mm_barrier_imp()

static __inline void mm_atomic_set_imp(u32_t *p, u32_t v)
{
    *p = v;
}

static __inline s32_t mm_atomic_dec_imp(u32_t *p)
{
    return --(*p);
}

static __inline s32_t mm_atomic_inc_imp(u32_t *p)
{
    return ++(*p);
}


#define MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL) \
    LM_BAR_WR32_ADDRESS((PDEV), ((u8_t *)PFDEV(PDEV)->context_info->array[VF_TO_PF_CID((PDEV),(CID))].cid_resc.mapped_cid_bar_addr + (DPM_TRIGER_TYPE)), (VAL))

#define MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw) \
    (LM_STATUS_SUCCESS) 


#define MM_ACQUIRE_SPQ_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring global SPQ lock\n");
#define MM_RELEASE_SPQ_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing global SPQ lock\n");
#define MM_ACQUIRE_SPQ_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring global SPQ lock\n");
#define MM_RELEASE_SPQ_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing global SPQ lock\n");

#define MM_ACQUIRE_CID_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring global CID lock\n");
#define MM_RELEASE_CID_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing global CID lock\n");

#define MM_ACQUIRE_REQUEST_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring ramrod lock\n");
#define MM_RELEASE_REQUEST_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing ramrod lock\n");

#define MM_ACQUIRE_PHY_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring phy lock\n");
#define MM_RELEASE_PHY_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing phy lock\n");
#define MM_ACQUIRE_PHY_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring phy lock\n");
#define MM_RELEASE_PHY_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing phy lock\n");

#define MM_ACQUIRE_MCP_LOCK_IMP(pdev)
#define MM_RELEASE_MCP_LOCK_IMP(pdev)

#define MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring isles control lock\n");
#define MM_RELEASE_ISLES_CONTROL_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing isles control lock\n");
#define MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring isles control lock\n");
#define MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing isles control lock\n");

#define MM_ACQUIRE_IND_REG_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring ind_reg lock\n");
#define MM_RELEASE_IND_REG_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing ind_reg lock\n");

#define MM_ACQUIRE_LOADER_LOCK_IMP() \
    DbgMessage(pdev, VERBOSEi, "Acquiring loader lock\n");
#define MM_RELEASE_LOADER_LOCK_IMP() \
    DbgMessage(pdev, VERBOSEi, "Releasing loader lock\n");

#define MM_ACQUIRE_SP_REQ_MGR_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring sp_req_mgr lock\n");
#define MM_RELEASE_SP_REQ_MGR_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing sp_req_mgr lock\n");

#define MM_ACQUIRE_SB_LOCK_IMP(pdev, sb_idx) \
    DbgMessage(pdev, VERBOSEi, "Acquiring sb lock\n");
#define MM_RELEASE_SB_LOCK_IMP(pdev, sb_idx) \
    DbgMessage(pdev, VERBOSEi, "Releasing sb lock\n");

#define MM_ACQUIRE_ETH_CON_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring eth con lock\n");
#define MM_RELEASE_ETH_CON_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing eth con lock\n");

static void mm_init_lock(struct _lm_device_t *_pdev,
                         mm_spin_lock_t *lock)
{
    /* Do nothing */
}

static __inline lm_status_t mm_acquire_lock(mm_spin_lock_t *spinlock)
{
    DbgMessage(NULL, VERBOSEi, "Acquiring lock #%d\n", (u32_t)spinlock);
    return LM_STATUS_SUCCESS;
}

static __inline lm_status_t mm_release_lock(mm_spin_lock_t *spinlock)
{
    DbgMessage(NULL, VERBOSEi, "Releasing lock #%d\n", (u32_t)spinlock);
    return LM_STATUS_SUCCESS;
}


#ifdef VF_INVOLVED

#define MM_ACQUIRE_PF_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring pf lock\n");
#define MM_RELEASE_PF_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing pf lock\n");

#define MM_ACQUIRE_VFS_STATS_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring vfs stats lock\n");
#define MM_RELEASE_VFS_STATS_LOCK_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing vfs stats lock\n");
#define MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Acquiring vfs stats lock\n");
#define MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(pdev) \
    DbgMessage(pdev, VERBOSEi, "Releasing vfs stats lock\n");

#endif /* VF_INVOLVED */


#define mm_er_initiate_recovery_imp(pdev) \
    (LM_STATUS_FAILURE)

#define mm_register_dpc_imp(_pdev, _func) \
    (LM_STATUS_FAILURE)

#define mm_empty_ramrod_received_imp(pdev, lm_cli_idx)

#define mm_debug_start_if_enabled_imp(pdev)
#define mm_debug_stop_if_started_imp(pdev)


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


