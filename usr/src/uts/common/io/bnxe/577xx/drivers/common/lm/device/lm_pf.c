/*******************************************************************************
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
 *
 * Module Description:
 *      This file contains functions that implement SR-IOV virtualization on
 *      the PF side
 *
 ******************************************************************************/

#ifdef VF_INVOLVED

#include "lm5710.h"
#include "lm_vf.h"
#include "577xx_int_offsets.h"
#include "command.h"

struct vf_pf_msg_hdr *lm_pf_validate_request_header(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, void * virt_buffer)
{
    struct vf_pf_msg_hdr * req_hdr = (struct vf_pf_msg_hdr *)virt_buffer;

    if (req_hdr->resp_msg_offset > vf_info->pf_vf_response.request_size) {
        req_hdr = NULL;
        DbgMessage(pdev, FATAL, "VF[%d]: Estimated size of incoming request(%d) exceeds buffer size(%d)\n",
                    vf_info->relative_vf_id, req_hdr->resp_msg_offset, vf_info->pf_vf_response.request_size);
    }
    return req_hdr;
}

lm_vf_info_t * lm_pf_find_vf_info_by_rel_id(struct _lm_device_t *pdev, u16_t relative_vf_id)
{
    lm_vf_info_t * vf_info = NULL;
    if (relative_vf_id < pdev->vfs_set.number_of_enabled_vfs) {
        vf_info = &pdev->vfs_set.vfs_array[relative_vf_id];
    } else {
        DbgMessage(pdev, FATAL, "lm_pf_find_vf_info_by_rel_id: VF[%d] is not enabled\n", relative_vf_id);
    }
    return vf_info;
}

lm_vf_info_t * lm_pf_find_vf_info_by_abs_id(struct _lm_device_t *pdev, u8_t abs_vf_id)
{
    lm_vf_info_t * vf_info = NULL;
    u16_t relative_vf_id = 0xFFFF;
    DbgMessage(pdev, WARN, "lm_pf_find_vf_info_by_abs_id: abs_vf_id:%d(%d)\n",abs_vf_id,pdev->hw_info.sriov_info.first_vf_in_pf);
    if (abs_vf_id < pdev->hw_info.sriov_info.first_vf_in_pf) {
        DbgBreak();
    }
    relative_vf_id = abs_vf_id - (u8_t)pdev->hw_info.sriov_info.first_vf_in_pf;
    if (relative_vf_id < pdev->vfs_set.number_of_enabled_vfs) {
        vf_info = &pdev->vfs_set.vfs_array[relative_vf_id];
    } else {
        DbgMessage(pdev, FATAL, "lm_pf_find_vf_info_by_abs_id: VF[a:%d,r:%d] is not enabled\n",abs_vf_id,relative_vf_id);
    }
    return vf_info;
}

lm_status_t lm_pf_download_standard_request(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, void* virt_buffer, u32_t length)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_hdr * requst_hdr = NULL;

    if(!(pdev && vf_info && virt_buffer)) {
        DbgMessage(pdev, FATAL, "PFVF request with invalid parameters: %p, %p, %p, d\n", pdev,vf_info,virt_buffer,length);
        DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
        return LM_STATUS_INVALID_PARAMETER;
    }
    
    if ((vf_info->pf_vf_response.req_resp_state != VF_PF_WAIT_FOR_START_REQUEST)
            && (vf_info->pf_vf_response.req_resp_state != VF_PF_WAIT_FOR_NEXT_CHUNK_OF_REQUEST)) {
        DbgMessage(pdev, FATAL, "VF[%d] does not expect PFVF request (%d)\n", vf_info->relative_vf_id, vf_info->pf_vf_response.req_resp_state);
        return LM_STATUS_FAILURE;
    }
    if (vf_info->pf_vf_response.req_resp_state == VF_PF_WAIT_FOR_START_REQUEST) {
        //requst_hdr = (struct vf_pf_msg_hdr *)virt_buffer;
        if (length >= sizeof(struct vf_pf_msg_hdr)) {
            requst_hdr = lm_pf_validate_request_header(pdev, vf_info, virt_buffer);
            if (requst_hdr != NULL) {
        vf_info->pf_vf_response.request_offset = 0;
            }
        } else {
            DbgMessage(pdev, FATAL, "VF[%d] received too short(%d) PFVF request\n", vf_info->relative_vf_id, length);
        }
    } else {
        requst_hdr = (struct vf_pf_msg_hdr *)vf_info->pf_vf_response.request_virt_addr;
    }

    if (requst_hdr != NULL) {
        if (length <= (vf_info->pf_vf_response.request_size - vf_info->pf_vf_response.request_offset)) {
    mm_memcpy((u8_t*)vf_info->pf_vf_response.request_virt_addr + vf_info->pf_vf_response.request_offset, virt_buffer, length);
    DbgMessage(pdev, WARN, "VF[%d]: lm_pf_download_standard_request: %d bytes from offset %d\n", vf_info->relative_vf_id,
                length, vf_info->pf_vf_response.request_offset);
    if (requst_hdr->resp_msg_offset > (vf_info->pf_vf_response.request_offset + length)) {
        lm_status = LM_STATUS_PENDING;
        vf_info->pf_vf_response.request_offset += length;
        vf_info->pf_vf_response.req_resp_state = VF_PF_WAIT_FOR_NEXT_CHUNK_OF_REQUEST;
    } else {
        vf_info->pf_vf_response.response_virt_addr = (u8_t*)vf_info->pf_vf_response.request_virt_addr + requst_hdr->resp_msg_offset;
        vf_info->pf_vf_response.request_offset = 0;
        vf_info->pf_vf_response.req_resp_state = VF_PF_REQUEST_IN_PROCESSING;
    }
        } else {
            lm_status = LM_STATUS_INVALID_PARAMETER;
            vf_info->pf_vf_response.req_resp_state = VF_PF_WAIT_FOR_START_REQUEST;
        }
    } else {
        lm_status = LM_STATUS_INVALID_PARAMETER;
    }
    return lm_status;
}
lm_status_t lm_pf_upload_standard_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, void* virt_buffer, u32_t length)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t response_rest;

    if(!(pdev && vf_info && virt_buffer)) {
        DbgMessage(pdev, FATAL, "PFVF rresponse with invalid parameters: %p, %p, %p, d\n", pdev,vf_info,virt_buffer,length);
        DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (length < sizeof(struct pf_vf_msg_resp))
    {
        DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
    }

    switch (vf_info->pf_vf_response.req_resp_state) {
    case VF_PF_WAIT_FOR_START_REQUEST:
    case VF_PF_WAIT_FOR_NEXT_CHUNK_OF_REQUEST:
        DbgMessage(pdev, WARN, "VF[%d]:lm_pf_upload_standard_response (LM_STATUS_FAILURE)\n",vf_info->relative_vf_id);
        lm_status = LM_STATUS_FAILURE;
        break;
    case VF_PF_REQUEST_IN_PROCESSING:
        DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
        if (length > sizeof(struct pf_vf_msg_resp)) 
        {
            length = sizeof(struct pf_vf_msg_resp);
        }
        mm_memcpy(virt_buffer, vf_info->pf_vf_response.response_virt_addr, length);
        break;
    case VF_PF_RESPONSE_READY:
        response_rest = vf_info->pf_vf_response.response_size - vf_info->pf_vf_response.response_offset;
        if (length <= response_rest) {
            vf_info->pf_vf_response.req_resp_state = VF_PF_WAIT_FOR_START_REQUEST;
        } else {
            length = response_rest;
        }
        mm_memcpy(virt_buffer, (u8_t*)vf_info->pf_vf_response.response_virt_addr + vf_info->pf_vf_response.response_offset, length);
        DbgMessage(pdev, WARN, "VF[%d]:lm_pf_upload_standard_response: %d bytes from offset %d\n",vf_info->relative_vf_id,length,
                    vf_info->pf_vf_response.response_offset);
        vf_info->pf_vf_response.response_offset += length;
        if (vf_info->pf_vf_response.response_offset == vf_info->pf_vf_response.response_size) 
        {
            vf_info->pf_vf_response.req_resp_state = VF_PF_WAIT_FOR_START_REQUEST;
        }
        break;
    default:
        DbgBreak();

    }

    return lm_status;
}

lm_status_t lm_pf_upload_standard_request(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, lm_address_t * phys_buffer, u32_t length)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    DbgMessage(pdev, WARN, "lm_pf_upload_standard_request is not implemented yet\n");
    return lm_status;
}

lm_status_t lm_pf_allocate_vfs(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t        mm_cli_idx = 0;
    u32_t       alloc_size = 0;
    u16_t       num_vfs = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    mm_cli_idx = LM_RESOURCE_COMMON;
    num_vfs = pdev->hw_info.sriov_info.total_vfs;

    pdev->vfs_set.number_of_enabled_vfs = 0;
    if (!num_vfs) {
        DbgMessage(pdev, WARN, "lm_pf_allocate_vfs: SRIOV capability is not found\n");
        return LM_STATUS_FAILURE;
    } else {
        DbgMessage(pdev, WARN, "lm_pf_allocate_vfs for %d VFs\n",num_vfs);
    }
    alloc_size = sizeof(lm_vf_info_t) * num_vfs;

    pdev->vfs_set.vfs_array = mm_alloc_mem(pdev, alloc_size, mm_cli_idx);
    if CHK_NULL(pdev->vfs_set.vfs_array)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero(pdev->vfs_set.vfs_array, alloc_size ) ;
    pdev->vfs_set.req_resp_size = (((sizeof(union vf_pf_msg) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
                                            + ((sizeof(union pf_vf_msg) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)) * num_vfs;
    pdev->vfs_set.req_resp_virt_addr = mm_alloc_phys_mem(pdev, pdev->vfs_set.req_resp_size,
                                                                    &pdev->vfs_set.req_resp_phys_addr, 0, LM_RESOURCE_COMMON);
    if CHK_NULL(pdev->vfs_set.req_resp_virt_addr)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }

    pdev->vfs_set.pf_fw_stats_set_data_sz = ((sizeof(struct per_queue_stats) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK) * num_vfs;
    pdev->vfs_set.pf_fw_stats_set_virt_data = mm_alloc_phys_mem(pdev, pdev->vfs_set.pf_fw_stats_set_data_sz,
                                                                    &pdev->vfs_set.pf_fw_stats_set_phys_data, 0, LM_RESOURCE_COMMON);
    if CHK_NULL(pdev->vfs_set.pf_fw_stats_set_virt_data)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }

    alloc_size = sizeof(lm_stats_fw_t) * num_vfs;
    pdev->vfs_set.mirror_stats_fw_set = mm_alloc_mem(pdev, alloc_size, mm_cli_idx);
    if CHK_NULL(pdev->vfs_set.mirror_stats_fw_set)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    pdev->vfs_set.rss_update_size = ((sizeof(struct eth_rss_update_ramrod_data) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK) * num_vfs;
    pdev->vfs_set.rss_update_virt_addr = mm_alloc_phys_mem(pdev, pdev->vfs_set.rss_update_size,
                                                                    &pdev->vfs_set.rss_update_phys_addr, 0, LM_RESOURCE_COMMON);
    if CHK_NULL(pdev->vfs_set.rss_update_virt_addr)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }

    if (pdev->hw_info.sriov_info.sriov_control & 0x0001) {
          lm_status = lm_pf_init_vfs(pdev, pdev->hw_info.sriov_info.num_vfs);
          DbgMessage(pdev, WARN, "SRIOV enable(after FLR): init %d VFs: status %d\n",pdev->hw_info.sriov_info.num_vfs,lm_status);
          if(lm_status != LM_STATUS_SUCCESS) {
              DbgBreak();
              return lm_status;
          } else {
              u16_t vf_idx;
              DbgMessage(pdev, WARN, "lm_pf_init_vfs returns OK\n");
              for (vf_idx = 0; vf_idx < pdev->hw_info.sriov_info.num_vfs; vf_idx++) {
#if 0
                  lm_status = lm_pf_enable_vf(pdev, pdev->hw_info.sriov_info.first_vf_in_pf + vf_idx);
                  if(lm_status != LM_STATUS_SUCCESS) {
                      DbgMessage(pdev, WARN, "SRIOV enable(after FLR): enable VF[%d]: status %d\n",vf_idx,lm_status);
                      DbgBreak();
                      return lm_status;
                  }                 
#endif
              }
          }
    }
    return lm_status;
}

lm_status_t lm_pf_init_vfs(struct _lm_device_t *pdev, u16_t num_vfs)
{
    lm_address_t    mem_phys;
    u8_t *          mem_virt;
    lm_status_t     lm_status = LM_STATUS_SUCCESS;
    u32_t           req_resp_size;
    u32_t           stats_size;
    u32_t           rss_upd_size;
    u16_t           vf_idx = 0;

    DbgBreakIf(!(pdev && num_vfs && pdev->vfs_set.vfs_array && pdev->vfs_set.req_resp_virt_addr && pdev->vfs_set.pf_fw_stats_set_virt_data));
    MM_ACQUIRE_VFS_STATS_LOCK(pdev);
    pdev->vfs_set.number_of_enabled_vfs = 0;
    mm_mem_zero(pdev->vfs_set.vfs_array, sizeof(lm_vf_info_t)*num_vfs);
    mm_mem_zero(pdev->vfs_set.mirror_stats_fw_set, sizeof(lm_stats_fw_t)*num_vfs);

    req_resp_size = ((sizeof(union vf_pf_msg) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
                                            + ((sizeof(union pf_vf_msg) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK);
    mem_phys = pdev->vfs_set.req_resp_phys_addr;
    mem_virt = pdev->vfs_set.req_resp_virt_addr;

    for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
        pdev->vfs_set.vfs_array[vf_idx].pf_vf_response.response_phys_addr = mem_phys;
        LM_INC64(&mem_phys, req_resp_size);
        pdev->vfs_set.vfs_array[vf_idx].pf_vf_response.request_virt_addr = mem_virt;
        mem_virt += req_resp_size;
        pdev->vfs_set.vfs_array[vf_idx].pf_vf_response.request_size = req_resp_size;
        pdev->vfs_set.vfs_array[vf_idx].pf_vf_response.req_resp_state = VF_PF_WAIT_FOR_START_REQUEST;
        pdev->vfs_set.vfs_array[vf_idx].relative_vf_id = (u8_t)vf_idx;
        pdev->vfs_set.vfs_array[vf_idx].abs_vf_id = (u8_t)(vf_idx + pdev->hw_info.sriov_info.first_vf_in_pf);
    }

    stats_size = (sizeof(struct per_queue_stats) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
    mem_phys = pdev->vfs_set.pf_fw_stats_set_phys_data;
    mem_virt = pdev->vfs_set.pf_fw_stats_set_virt_data;
    for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
        pdev->vfs_set.vfs_array[vf_idx].vf_stats.pf_fw_stats_phys_data = mem_phys;
        LM_INC64(&mem_phys, stats_size);
        pdev->vfs_set.vfs_array[vf_idx].vf_stats.pf_fw_stats_virt_data = (struct per_queue_stats *)mem_virt;
        mem_virt += stats_size;
        pdev->vfs_set.vfs_array[vf_idx].vf_stats.mirror_stats_fw = pdev->vfs_set.mirror_stats_fw_set + sizeof(lm_stats_fw_t) * vf_idx;
    }

    rss_upd_size = (sizeof(struct eth_rss_update_ramrod_data) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
    mem_phys = pdev->vfs_set.rss_update_phys_addr;
    mem_virt = pdev->vfs_set.rss_update_virt_addr;
    for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
        pdev->vfs_set.vfs_array[vf_idx].vf_slowpath_info.slowpath_data.rss_rdata_phys = mem_phys;
        LM_INC64(&mem_phys, rss_upd_size);
        pdev->vfs_set.vfs_array[vf_idx].vf_slowpath_info.slowpath_data.rss_rdata = (struct eth_rss_update_ramrod_data *)mem_virt;
        mem_virt += rss_upd_size;
    }
    pdev->vfs_set.number_of_enabled_vfs = num_vfs;
    mm_mem_zero(pdev->pf_resources.free_sbs,sizeof(pdev->pf_resources.free_sbs));
    mm_mem_zero(pdev->pf_resources.free_fw_clients,sizeof(pdev->pf_resources.free_fw_clients));
    mm_mem_zero(pdev->pf_resources.free_sw_clients,sizeof(pdev->pf_resources.free_sw_clients));
    MM_RELEASE_VFS_STATS_LOCK(pdev);
    return lm_status;
}

#if 0
lm_status_t lm_pf_clear_vfs(struct _lm_device_t * pf_dev)
{
    /* TODO: Clean VF Database for FLR needs? */
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t base_vfid, vfid;
    u16_t pretend_val;
    u16_t ind_cids, start_cid, end_cid;

    DbgMessage(pf_dev, FATAL, "vf disable\n");
    start_cid = (((1 << LM_VF_MAX_RVFID_SIZE) | 0) <<  LM_VF_CID_WND_SIZE); //1st possible abs VF_ID
    end_cid = (((1 << LM_VF_MAX_RVFID_SIZE) | 63) <<  LM_VF_CID_WND_SIZE); //last possible abs VF_ID
    DbgMessage(pf_dev, FATAL, "vf disable: clear VFs connections from %d till %d\n",start_cid, end_cid);
    for (ind_cids = MAX_ETH_CONS; ind_cids < ETH_MAX_RX_CLIENTS_E2; ind_cids++) {
        pf_dev->vars.connections[ind_cids].con_state = LM_CON_STATE_CLOSE;
    }

    if (lm_is_function_after_flr(pf_dev)) {
        pf_dev->vfs_set.number_of_enabled_vfs = 0;
        DbgMessage(pf_dev, FATAL, "vf disable called on a flred function - not much we can do here... \n");
        return LM_STATUS_SUCCESS;
    }
    /* if MCP does not exist for each vf in pf, need to pretend to it and disable igu vf_msix and internal vfid enable bit */
    if (GET_FLAGS( pf_dev->params.test_mode, TEST_MODE_NO_MCP)){
        DbgMessage(pf_dev, FATAL, "bootcode is down fix sriov disable.\n");
        base_vfid = pf_dev->hw_info.sriov_info.first_vf_in_pf;
        for (vfid = base_vfid; vfid < base_vfid + pf_dev->vfs_set.number_of_enabled_vfs; vfid++ ) {
            pretend_val = ABS_FUNC_ID(pf_dev) | (1<<3) | (vfid << 4);
            lm_pretend_func(pf_dev, pretend_val);

            REG_WR(pf_dev, IGU_REG_PCI_VF_MSIX_EN, 0);
            REG_WR(pf_dev, IGU_REG_PCI_VF_MSIX_FUNC_MASK, 0);
            REG_WR(pf_dev, PGLUE_B_REG_INTERNAL_VFID_ENABLE, 0);

            lm_pretend_func(pf_dev, ABS_FUNC_ID(pf_dev) );
        }

        /* This is a clear-on-write register, therefore we actually write 1 to the bit we want to reset */
        REG_WR(pf_dev, 0x24d8, 1<<29);

        REG_WR(pf_dev, PGLUE_B_REG_SR_IOV_DISABLED_REQUEST_CLR ,(1<<ABS_FUNC_ID(pf_dev)));
        //REG_WR(pf_dev, PGLUE_B_REG_DISABLE_FLR_SRIOV_DISABLED, PGLUE_B_DISABLE_FLR_SRIOV_DISABLED_REG_DISABLE_SRIOV_DISABLED_REQUEST);*/
    }
    pf_dev->vfs_set.number_of_enabled_vfs = 0;
    return lm_status;
}
#endif

lm_status_t lm_pf_set_vf_ctx(struct _lm_device_t *pdev, u16_t vf_id, void* ctx)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);
    DbgBreakIf(!vf_info);
    if (vf_info != NULL) {
        vf_info->um_ctx = ctx;
        vf_info->vf_si_state = PF_SI_WAIT_FOR_ACQUIRING_REQUEST;
        vf_info->pf_vf_response.req_resp_state = VF_PF_WAIT_FOR_START_REQUEST;
    } else {
        lm_status = LM_STATUS_FAILURE;
    }
    return lm_status;
}

lm_status_t lm_pf_set_vf_stat_id(struct _lm_device_t *pdev,
                                   u16_t vf_id,
                                   u8_t base_fw_stats_id)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);
    DbgBreakIf(!vf_info);
    if (vf_info != NULL) {
        vf_info->base_fw_stats_id = base_fw_stats_id;
        DbgMessage(pdev, WARN, "VF[%d]: Stat ID: %d(FW)\n", vf_id, base_fw_stats_id);
    } else {
        lm_status = LM_STATUS_FAILURE;
    }
    return lm_status;
}

u8_t lm_pf_is_vf_mac_set(struct _lm_device_t *pdev, u16_t vf_id)
{
    u8_t is_mac_set = FALSE;
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);
    DbgBreakIf(!vf_info);
    if (vf_info != NULL) {
        is_mac_set = vf_info->is_mac_set;
    }
    return is_mac_set;
}

lm_status_t lm_pf_set_vf_base_cam_idx(struct _lm_device_t *pdev, u16_t vf_id, u32_t base_cam_idx)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);
    DbgBreakIf(!vf_info);
    if (vf_info != NULL) {
        vf_info->base_cam_offset = base_cam_idx;
    } else {
        lm_status = LM_STATUS_FAILURE;
    }
    return lm_status;
}

u32_t lm_pf_get_sw_client_idx_from_cid(struct _lm_device_t *pdev, u32_t cid)
{
    u32_t client_info_idx = 0xFFFFFFFF;
    u8_t  abs_vf_id = 0xff;
    u8_t  vf_q_id = 0xff;
    lm_vf_info_t * vf_info = NULL;

    DbgBreakIf(!IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev));

    /* Either MP is disabled OR enabled but not a tx-only connection */
    if (cid < MAX_RX_CHAIN(pdev)) 
    {
        client_info_idx = cid;
    } 
    else 
    {
        abs_vf_id = GET_ABS_VF_ID_FROM_PF_CID(cid);
        vf_q_id = GET_VF_Q_ID_FROM_PF_CID(cid);
        vf_info = lm_pf_find_vf_info_by_abs_id(pdev, abs_vf_id);
        DbgBreakIf(!vf_info);
        client_info_idx = LM_SW_VF_CLI_ID(vf_info, vf_q_id);
    }
    return client_info_idx;
}

u32_t lm_pf_get_fw_client_idx_from_cid(struct _lm_device_t *pdev, u32_t cid)
{
    u32_t client_info_idx = 0xFFFFFFFF;
    u8_t  abs_vf_id = 0xff;
    u8_t  vf_q_id = 0xff;
    lm_vf_info_t * vf_info = NULL;

    DbgBreakIf(!IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev));
  
    if (cid < MAX_RX_CHAIN(pdev)) {
        client_info_idx = LM_FW_CLI_ID(pdev,cid);
    } else {
        abs_vf_id = GET_ABS_VF_ID_FROM_PF_CID(cid);
        vf_q_id = GET_VF_Q_ID_FROM_PF_CID(cid);
        vf_info = lm_pf_find_vf_info_by_abs_id(pdev, abs_vf_id);
        DbgBreakIf(!vf_info);
        client_info_idx = LM_FW_VF_CLI_ID(vf_info, vf_q_id);
    }
    return client_info_idx;
}

u8_t lm_vf_get_free_resource(u32_t * resource, u8_t min_num, u8_t max_num, u8_t num)
{
    u8_t i,j;
    u8_t base_value = 0xff;

    for (i = min_num; i <= (max_num - num); i++) {
        u8_t  ind,offset;
        for (j = 0; j < num; j++) {
            ind = (i + j) / ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
            offset = (i+j) % ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
            if (resource[ind] & (1 << offset)) {
                break;
            }
        }
        if (j == num) {
            base_value = i;
            break;
        }
    }
    return base_value;
}

void lm_vf_acquire_resource(u32_t * presource, u8_t base_value, u8_t num)
{
    int i,ind,offset;
    for (i = base_value; i < (base_value + num); i++) {
        ind = i / ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
        offset = i % ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
        presource[ind] |= (1 << offset);
    }

    return;
}

u8_t lm_vf_get_resource_value(u32_t * presource, u8_t base_value)
{
    u8_t value;
    int ind,offset;

    ind = base_value / ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
    offset = base_value % ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
    value = presource[ind] & (1 << offset);

    return value;
}

void lm_vf_release_resource(u32_t * presource, u8_t base_value, u8_t num)
{
    int i,ind,offset;
    for (i = base_value; i < (base_value + num); i++) {
        ind = i / ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
        offset = i % ELEM_OF_RES_ARRAY_SIZE_IN_BITS;
        presource[ind] &= ~(1 << offset);
    }

    return;
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))
#endif

u8_t lm_pf_acquire_vf_chains_resources(struct _lm_device_t *pdev, u16_t vf_id, u32_t num_chains)
{
    u32_t chain_idx;
    u8_t min_ndsb;
    u8_t min_fw_client, current_fw_client;
    u8_t min_sw_client = MAX_RX_CHAIN(pdev);
    u8_t client_info_entries;
    
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);

    MM_ACQUIRE_PF_LOCK(pdev);
    vf_info->num_allocated_chains = 0;
    min_ndsb = pdev->params.max_pf_sb_cnt;
    min_fw_client = pdev->params.max_pf_fw_client_cnt;
    DbgBreakIf(pdev->params.fw_client_cnt <= pdev->params.max_pf_fw_client_cnt);
    client_info_entries = pdev->params.fw_client_cnt;
    
    if (min_sw_client < pdev->params.max_pf_fw_client_cnt) 
    {
        min_sw_client = pdev->params.max_pf_fw_client_cnt;
    }
    for (chain_idx = 0; chain_idx < num_chains; chain_idx++) {
        vf_info->vf_chains[chain_idx].sw_ndsb = lm_vf_get_free_resource(pdev->pf_resources.free_sbs, min_ndsb,
                                                                        pdev->params.fw_sb_cnt, 1);
        if (vf_info->vf_chains[chain_idx].sw_ndsb == 0xFF) {
            DbgMessage(pdev, FATAL, "No SBs from %d to %d\n",min_ndsb,pdev->params.fw_sb_cnt);
            break;
        }
        vf_info->vf_chains[chain_idx].fw_ndsb = LM_FW_SB_ID(pdev,vf_info->vf_chains[chain_idx].sw_ndsb);
        min_ndsb = vf_info->vf_chains[chain_idx].sw_ndsb + 1;
#if 0
        current_fw_client = lm_vf_get_free_resource(pdev->pf_resources.free_fw_clients, min_fw_client,
                                                                        pdev->params.fw_client_cnt, 1);
        if (current_fw_client == 0xFF) {

            DbgMessage(pdev, FATAL, "No FW Clients from %d to %d\n",min_fw_client,pdev->params.fw_client_cnt);
            break;
        }
#endif
        current_fw_client = vf_info->vf_chains[chain_idx].sw_client_id = lm_vf_get_free_resource(pdev->pf_resources.free_sw_clients, min_sw_client, client_info_entries, 1);
        if (vf_info->vf_chains[chain_idx].sw_client_id == 0xFF) {

            DbgMessage(pdev, FATAL, "No Clients from %d to %d\n",min_sw_client,client_info_entries);
            break;
        }

        vf_info->vf_chains[chain_idx].fw_client_id = LM_FW_CLI_ID(pdev,current_fw_client);
        vf_info->vf_chains[chain_idx].fw_qzone_id =  LM_FW_DHC_QZONE_ID(pdev, vf_info->vf_chains[chain_idx].sw_ndsb);

        min_fw_client = current_fw_client + 1;
        min_sw_client = vf_info->vf_chains[chain_idx].sw_client_id + 1;
        vf_info->num_allocated_chains++;
    }
    if (vf_info->num_allocated_chains) {
        for (chain_idx = 0; chain_idx < vf_info->num_allocated_chains; chain_idx++) {
            lm_vf_acquire_resource(pdev->pf_resources.free_sbs, vf_info->vf_chains[chain_idx].sw_ndsb, 1);
            lm_vf_acquire_resource(pdev->pf_resources.free_fw_clients, vf_info->vf_chains[chain_idx].fw_client_id - pdev->params.base_fw_client_id, 1);
            lm_vf_acquire_resource(pdev->pf_resources.free_sw_clients, vf_info->vf_chains[chain_idx].sw_client_id, 1);
            DbgMessage(pdev, WARN, "VF[%d(rel)] received resourses for chain %d: SW_NDSB=%d, FW_CLIENT_ID=%d, SW_CLIENT_ID=%d\n",
                        vf_id, 
                        chain_idx, 
                        vf_info->vf_chains[chain_idx].sw_ndsb, 
                        vf_info->vf_chains[chain_idx].fw_client_id - pdev->params.base_fw_client_id,
                        vf_info->vf_chains[chain_idx].sw_client_id);
        }
    }

    MM_RELEASE_PF_LOCK(pdev);
    return vf_info->num_allocated_chains;
}

void lm_pf_release_vf_chains_resources(struct _lm_device_t *pdev, u16_t vf_id)
{
    u8_t num_chains, chain_idx;
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);

    num_chains = vf_info->num_allocated_chains;
    if (!vf_info->was_malicious) 
    {
        MM_ACQUIRE_PF_LOCK(pdev);
        for (chain_idx = 0; chain_idx < num_chains; chain_idx++) 
        {
            lm_vf_release_resource(pdev->pf_resources.free_sbs, vf_info->vf_chains[chain_idx].sw_ndsb, 1);
            lm_vf_release_resource(pdev->pf_resources.free_fw_clients, vf_info->vf_chains[chain_idx].fw_client_id - pdev->params.base_fw_client_id, 1);
            lm_vf_release_resource(pdev->pf_resources.free_sw_clients, vf_info->vf_chains[chain_idx].sw_client_id, 1);
        }
        MM_RELEASE_PF_LOCK(pdev);
    }
    return;
}

void lm_pf_release_separate_vf_chain_resources(struct _lm_device_t *pdev, u16_t vf_id, u8_t chain_num)
{
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_rel_id(pdev, vf_id);

    if (!vf_info->was_malicious) 
    {
        if (chain_num < vf_info->num_allocated_chains) 
        {
            MM_ACQUIRE_PF_LOCK(pdev);
            lm_vf_release_resource(pdev->pf_resources.free_sbs, vf_info->vf_chains[chain_num].sw_ndsb, 1);
            lm_vf_release_resource(pdev->pf_resources.free_fw_clients, vf_info->vf_chains[chain_num].fw_client_id - pdev->params.base_fw_client_id, 1);
            lm_vf_release_resource(pdev->pf_resources.free_sw_clients, vf_info->vf_chains[chain_num].sw_client_id, 1);
            MM_RELEASE_PF_LOCK(pdev);
        }
    }
    return;
}

void lm_pf_init_vf_client(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t q_id)
{

    ecore_init_mac_obj(pdev,
                   &pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_id)].mac_obj,
                   LM_FW_VF_CLI_ID(vf_info,q_id),
                   LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_id),
                   FUNC_ID(pdev),
                   LM_SLOWPATH(pdev, mac_rdata)[LM_CLI_IDX_NDIS],
                   LM_SLOWPATH_PHYS(pdev, mac_rdata)[LM_CLI_IDX_NDIS],
                   ECORE_FILTER_MAC_PENDING,
                   (unsigned long *)&pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_id)].sp_mac_state,
                   ECORE_OBJ_TYPE_RX_TX,
                   &pdev->slowpath_info.macs_pool);

    if (!CHIP_IS_E1(pdev))
    {
        ecore_init_vlan_mac_obj(pdev,
                           &pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_id)].mac_vlan_obj,
                           LM_FW_VF_CLI_ID(vf_info,q_id),
                           LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_id),
                           FUNC_ID(pdev),
                           LM_SLOWPATH(pdev, mac_rdata)[LM_CLI_IDX_NDIS],
                           LM_SLOWPATH_PHYS(pdev, mac_rdata)[LM_CLI_IDX_NDIS],
                           ECORE_FILTER_VLAN_MAC_PENDING,
                           (unsigned long *)&pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_id)].sp_mac_state,
                           ECORE_OBJ_TYPE_RX_TX,
                           &pdev->slowpath_info.macs_pool,
                           &pdev->slowpath_info.vlans_pool);
    }

    return;
}

void lm_pf_init_vf_slow_path(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{

    ecore_init_rss_config_obj(pdev,
                              &vf_info->vf_slowpath_info.rss_conf_obj,
                              LM_FW_VF_CLI_ID(vf_info, LM_SW_LEADING_RSS_CID(pdev)),
                              LM_VF_Q_ID_TO_PF_CID(pdev, vf_info,LM_SW_LEADING_RSS_CID(pdev)),
                              vf_info->abs_vf_id,
                              8 + vf_info->abs_vf_id,
                              LM_VF_SLOWPATH(vf_info, rss_rdata),
                              LM_VF_SLOWPATH_PHYS(vf_info, rss_rdata),
                              ECORE_FILTER_RSS_CONF_PENDING,
                              (unsigned long *)&vf_info->vf_slowpath_info.sp_rss_state,
                              ECORE_OBJ_TYPE_RX);
    vf_info->was_malicious = FALSE;
    return;
}

lm_status_t lm_pf_vf_wait_for_stats_ready(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    return lm_wait_state_change(pdev, &vf_info->vf_stats.vf_stats_state, VF_STATS_REQ_READY);
}

lm_status_t lm_pf_init_vf_client_init_data(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t q_id,
                                           struct sw_vf_pf_rxq_params * rxq_params,
                                           struct sw_vf_pf_txq_params * txq_params)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;
    struct client_init_ramrod_data *
                    client_init_data_virt = NULL;
    lm_address_t    q_addr;
    u16_t           client_interrupt_moderation_level;

    client_init_data_virt = &(pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_id)].client_init_data_virt->init_data);

    if CHK_NULL(client_init_data_virt)
    {
        return LM_STATUS_FAILURE;
    }

    /* General Structure */

    client_init_data_virt->general.activate_flg          = 1;
    client_init_data_virt->general.client_id             = LM_FW_VF_CLI_ID(vf_info, q_id);
    client_init_data_virt->general.is_fcoe_flg           = FALSE;
    client_init_data_virt->general.statistics_counter_id = LM_FW_VF_STATS_CNT_ID(vf_info);
    client_init_data_virt->general.statistics_en_flg     = TRUE;
    client_init_data_virt->general.sp_client_id          = LM_FW_CLI_ID(pdev, LM_SW_LEADING_RSS_CID(pdev));
    client_init_data_virt->general.mtu                   = mm_cpu_to_le16((u16_t)rxq_params->mtu);
    client_init_data_virt->general.func_id               = 8 + vf_info->abs_vf_id;
    client_init_data_virt->general.cos                   = 0;//The connection cos, if applicable only if STATIC_COS is set
    client_init_data_virt->general.traffic_type          = LLFC_TRAFFIC_TYPE_NW;
    client_init_data_virt->general.fp_hsi_ver            = vf_info->fp_hsi_ver;

    client_init_data_virt->rx.status_block_id               = LM_FW_VF_SB_ID(vf_info,q_id); //LM_FW_VF_SB_ID(vf_info, LM_VF_Q_TO_SB_ID(vf_info,q_id));
    client_init_data_virt->rx.client_qzone_id               = LM_FW_VF_QZONE_ID(vf_info, q_id);
   // client_init_data_virt->rx.tpa_en_flg                    = FALSE;
    client_init_data_virt->rx.max_agg_size                  = mm_cpu_to_le16(0); /* TPA related only  */;
    client_init_data_virt->rx.extra_data_over_sgl_en_flg    = FALSE;
    if (rxq_params->flags & SW_VFPF_QUEUE_FLG_CACHE_ALIGN) {
        client_init_data_virt->rx.cache_line_alignment_log_size = rxq_params->cache_line_log;
    } else {
        client_init_data_virt->rx.cache_line_alignment_log_size = (u8_t)LOG2(CACHE_LINE_SIZE/* TODO mm_get_cache_line_alignment()*/);
    }
    
    if (pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC)
    {
        client_interrupt_moderation_level = vf_info->current_interrupr_moderation;
        if ((rxq_params->flags & SW_VFPF_QUEUE_FLG_DHC)) {
            client_init_data_virt->rx.enable_dynamic_hc = TRUE;
        } else {
            client_init_data_virt->rx.enable_dynamic_hc = FALSE;
            if (client_interrupt_moderation_level == VPORT_INT_MOD_ADAPTIVE) 
            {
                client_interrupt_moderation_level = VPORT_INT_MOD_UNDEFINED;
            }
        }
    }
    else
    {
        client_init_data_virt->rx.enable_dynamic_hc = FALSE;
        client_interrupt_moderation_level = VPORT_INT_MOD_OFF;
    }
    lm_pf_update_vf_ndsb(pdev, vf_info, q_id, client_interrupt_moderation_level);

    client_init_data_virt->rx.outer_vlan_removal_enable_flg = IS_MULTI_VNIC(pdev)? TRUE: FALSE;
    client_init_data_virt->rx.inner_vlan_removal_enable_flg = TRUE; //= !pdev->params.keep_vlan_tag;

    client_init_data_virt->rx.state = CLIENT_INIT_RX_DATA_ACCEPT_ANY_VLAN;   /*If VF L2 client established without "accept_any_vlan" flag, the firmware is trying */
    client_init_data_virt->tx.state = CLIENT_INIT_TX_DATA_ACCEPT_ANY_VLAN;   /*to match packets with both MAC and VLAN, fails and send the packet to 
                                                                               the network (transfer leakage). 
                                                                               The "accept_any_vlan" is only set later in the "set rx mode" command, 
                                                                               and then the TX-switching is working again.*/

    q_addr.as_u64 = rxq_params->rxq_addr;
    client_init_data_virt->rx.bd_page_base.lo= mm_cpu_to_le32(q_addr.as_u32.low);
    client_init_data_virt->rx.bd_page_base.hi= mm_cpu_to_le32(q_addr.as_u32.high);

    q_addr.as_u64 = rxq_params->rcq_addr;
    client_init_data_virt->rx.cqe_page_base.lo = mm_cpu_to_le32(q_addr.as_u32.low);
    client_init_data_virt->rx.cqe_page_base.hi = mm_cpu_to_le32(q_addr.as_u32.high);


    if (!q_id) {
        client_init_data_virt->rx.is_leading_rss = TRUE;
    }
    client_init_data_virt->rx.is_approx_mcast = TRUE;

    client_init_data_virt->rx.approx_mcast_engine_id = 8 + vf_info->abs_vf_id;
    client_init_data_virt->rx.rss_engine_id          = 8 + vf_info->abs_vf_id;

    client_init_data_virt->rx.max_bytes_on_bd = mm_cpu_to_le16((rxq_params->buf_sz) - (pdev)->params.rcv_buffer_offset);


    /* Status block index init we do for Rx + Tx together so that we ask which cid we are only once */
    client_init_data_virt->rx.rx_sb_index_number = rxq_params->sb_index;
    client_init_data_virt->tx.tx_sb_index_number = txq_params->sb_index;

    /* TX Data (remaining , sb index above...)  */
    /* ooo cid doesn't have a tx chain... */
    q_addr.as_u64 = txq_params->txq_addr;
    client_init_data_virt->tx.tx_bd_page_base.hi = mm_cpu_to_le32(q_addr.as_u32.high);
    client_init_data_virt->tx.tx_bd_page_base.lo = mm_cpu_to_le32(q_addr.as_u32.low);

    client_init_data_virt->tx.tx_status_block_id = LM_FW_VF_SB_ID(vf_info,txq_params->vf_sb);

    client_init_data_virt->tx.enforce_security_flg = TRUE;//FALSE; /* TBD: turn on for KVM VF? */

    /* Tx Switching... */
    client_init_data_virt->tx.tss_leading_client_id = LM_FW_VF_CLI_ID(vf_info, 0);
#ifdef __LINUX
    client_init_data_virt->tx.tx_switching_flg = FALSE;
    client_init_data_virt->tx.anti_spoofing_flg = FALSE;
#else
    client_init_data_virt->tx.tx_switching_flg = TRUE;
    client_init_data_virt->tx.anti_spoofing_flg = TRUE;
#endif
    /* FC */
#if 0
    if (pdev->params.l2_fw_flow_ctrl)
    {
        u16_t low_thresh  = mm_cpu_to_le16(min(250, ((u16_t)(LM_RXQ(pdev, cid).common.desc_cnt))/4));
        u16_t high_thresh = mm_cpu_to_le16(min(350, ((u16_t)(LM_RXQ(pdev, cid).common.desc_cnt))/2));

        client_init_data_virt->fc.cqe_pause_thr_low  = low_thresh;
        client_init_data_virt->fc.bd_pause_thr_low   = low_thresh;
        client_init_data_virt->fc.sge_pause_thr_low  = 0;
        client_init_data_virt->fc.rx_cos_mask        = 1;
        client_init_data_virt->fc.cqe_pause_thr_high = high_thresh;
        client_init_data_virt->fc.bd_pause_thr_high  = high_thresh;
        client_init_data_virt->fc.sge_pause_thr_high = 0;
    }
#endif

    client_init_data_virt->tx.refuse_outband_vlan_flg = 0;

    // for encapsulated packets
    // the hw ip id will be the inner ip id, the hw will incremnet the inner ip id
    // this means that if the outer ip header is ipv4, its ip id will not be incremented.
    client_init_data_virt->tx.tunnel_lso_inc_ip_id = INT_HEADER;
    // In case of non-Lso encapsulated packets with L4 checksum offload, the pseudo checksum location - on BD
    client_init_data_virt->tx.tunnel_non_lso_pcsum_location = CSUM_ON_BD;
    // In case of non-Lso encapsulated packets with outer L3 ip checksum offload, the pseudo checksum location - on BD
    client_init_data_virt->tx.tunnel_non_lso_outer_ip_csum_location = CSUM_ON_BD;

    return lm_status;
}

u8_t lm_pf_is_sriov_valid(struct _lm_device_t *pdev)
{
    u8_t res = FALSE;
    if (IS_PFDEV(pdev)) {
        if (pdev->hw_info.sriov_info.total_vfs) {
            DbgMessage(pdev, FATAL, "The card has valid SRIOV caps\n");
            res = TRUE;
        } else {
            DbgMessage(pdev, FATAL, "The card has not valid SRIOV caps\n");
            res = FALSE;
        }
    } else {
        DbgMessage(pdev, FATAL, "Request of validity SRIOV caps is not applicable for VF\n");
        res = FALSE;
    }
    return res;
}

u8_t lm_pf_allocate_vf_igu_sbs(lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t num_of_igu_sbs)
{
    u8_t    num_of_vf_desired_vf_chains;
    u8_t    idx;
    u8_t    starting_from = 0;
    if ((pdev == NULL) || (vf_info == NULL)) 
    {
        DbgBreak();
        return 0;
    }
    vf_info->num_igu_sb_available = lm_pf_get_vf_available_igu_blocks(pdev);
    if (vf_info->num_igu_sb_available == 0) 
    {
        return 0;
    }
    
    num_of_vf_desired_vf_chains = min(vf_info->num_igu_sb_available, LM_VF_CHAINS_PER_PF(pdev));
    num_of_vf_desired_vf_chains = min(num_of_vf_desired_vf_chains, num_of_igu_sbs);
    MM_ACQUIRE_PF_LOCK(pdev);
    for (idx = 0; idx < num_of_vf_desired_vf_chains; idx++) 
    {
        starting_from = vf_info->vf_chains[idx].igu_sb_id = lm_pf_get_next_free_igu_block_id(pdev, starting_from);
        if (starting_from == 0xFF) 
        {
            break;
        }
        lm_pf_acquire_vf_igu_block(pdev, starting_from, vf_info->abs_vf_id, idx);        
    }    
    MM_RELEASE_PF_LOCK(pdev);
    num_of_vf_desired_vf_chains = idx;
#if 0
    vf_info->num_igu_sb_available = pdev->hw_info.intr_blk_info.igu_info.vf_igu_info[vf_info->abs_vf_id].igu_sb_cnt;
    num_of_vf_desired_vf_chains = min(vf_info->num_igu_sb_available, num_of_igu_sbs);
    for (idx = 0; idx < num_of_vf_desired_vf_chains; idx++) 
    {
        vf_info->vf_chains[idx].igu_sb_id = pdev->hw_info.intr_blk_info.igu_info.vf_igu_info[vf_info->abs_vf_id].igu_base_sb + idx;
    }
#endif    
    return num_of_vf_desired_vf_chains;
}

void lm_pf_release_vf_igu_sbs(struct _lm_device_t *pdev, struct _lm_vf_info_t *vf_info)
{
    return;
}

u8_t lm_pf_get_max_number_of_vf_igu_sbs(lm_device_t *pdev)
{
    u8_t max_igu_sbs = pdev->hw_info.sriov_info.total_vfs 
        * pdev->hw_info.intr_blk_info.igu_info.vf_igu_info[0].igu_sb_cnt;
    return max_igu_sbs;
}

u8_t lm_pf_get_next_free_igu_block_id(lm_device_t *pdev, u8_t starting_from)
{
    u8_t igu_sb_idx;
    u8_t igu_free_sb_id = 0xFF;
    for (igu_sb_idx = starting_from; igu_sb_idx < IGU_REG_MAPPING_MEMORY_SIZE; igu_sb_idx++ ) 
    {
        lm_igu_block_t * lm_igu_sb = &IGU_SB(pdev,igu_sb_idx);
        if (lm_igu_sb->status & LM_IGU_STATUS_AVAILABLE) 
        {
            if (!(lm_igu_sb->status & LM_IGU_STATUS_PF) && !(lm_igu_sb->status & LM_IGU_STATUS_BUSY)) 
            {
                igu_free_sb_id = igu_sb_idx;
                break;
            }            
        }
    }
    return igu_free_sb_id;
}

void lm_pf_clear_vf_igu_blocks(lm_device_t *pdev)
{
    u8_t igu_sb_idx;
    for (igu_sb_idx = 0; igu_sb_idx < IGU_REG_MAPPING_MEMORY_SIZE; igu_sb_idx++ ) 
    {
        lm_igu_block_t * lm_igu_sb = &IGU_SB(pdev,igu_sb_idx);
        if (lm_igu_sb->status & LM_IGU_STATUS_AVAILABLE) 
        {
            if (!(lm_igu_sb->status & LM_IGU_STATUS_PF)) 
            {
                REG_WR(PFDEV(pdev), IGU_REG_MAPPING_MEMORY + 4*igu_sb_idx, 0);
                lm_igu_sb->vf_number = lm_igu_sb->vector_number = 0xFF;
                lm_igu_sb->status &= ~LM_IGU_STATUS_BUSY;
            }            
        }
    }
    return;
}

u8_t lm_pf_release_vf_igu_block(lm_device_t *pdev, u8_t igu_sb_idx)
{
    lm_igu_block_t * lm_igu_sb = &IGU_SB(pdev,igu_sb_idx);
    u8_t res = FALSE;
    
    if (!(lm_igu_sb->status & LM_IGU_STATUS_PF) &&  (lm_igu_sb->status & LM_IGU_STATUS_AVAILABLE) && (igu_sb_idx < IGU_REG_MAPPING_MEMORY_SIZE)) 
    {
        REG_WR(PFDEV(pdev), IGU_REG_MAPPING_MEMORY + 4*igu_sb_idx, 0);
        lm_igu_sb->vf_number = lm_igu_sb->vector_number = 0xFF;
        lm_igu_sb->status &= ~LM_IGU_STATUS_BUSY;
        res = TRUE;
    }
    else
    {
        DbgBreak();
    }
    return res;
}

u8_t lm_pf_acquire_vf_igu_block(lm_device_t *pdev, u8_t igu_sb_idx, u8_t abs_vf_id, u8_t vector_number)
{
    lm_igu_block_t * lm_igu_sb = &IGU_SB(pdev,igu_sb_idx);
    u8_t res    = FALSE;
    u32_t value = 0;
    
    if (!(lm_igu_sb->status & LM_IGU_STATUS_PF) &&  (lm_igu_sb->status & LM_IGU_STATUS_AVAILABLE)
        && !(lm_igu_sb->status & LM_IGU_STATUS_BUSY) && (igu_sb_idx < IGU_REG_MAPPING_MEMORY_SIZE)) 
    {
        value = (IGU_REG_MAPPING_MEMORY_FID_MASK & (abs_vf_id << IGU_REG_MAPPING_MEMORY_FID_SHIFT))
                    | (IGU_REG_MAPPING_MEMORY_VECTOR_MASK & (vector_number << IGU_REG_MAPPING_MEMORY_VECTOR_SHIFT))
                    | IGU_REG_MAPPING_MEMORY_VALID;
        REG_WR(PFDEV(pdev), IGU_REG_MAPPING_MEMORY + 4*igu_sb_idx, value);
        lm_igu_sb->vf_number = abs_vf_id;
        lm_igu_sb->vector_number = vector_number;
        lm_igu_sb->status |= LM_IGU_STATUS_BUSY;
        res = TRUE;
    }
    else
    {
        DbgBreak();
    }
    return res;
}

u8_t lm_pf_get_vf_available_igu_blocks(lm_device_t *pdev)
{
    u8_t igu_sb_idx;
    u8_t available_igu_sbs = 0; 
    for (igu_sb_idx = 0; igu_sb_idx < IGU_REG_MAPPING_MEMORY_SIZE; igu_sb_idx++ ) 
    {
        lm_igu_block_t * lm_igu_sb = &IGU_SB(pdev,igu_sb_idx);
        if (lm_igu_sb->status & LM_IGU_STATUS_AVAILABLE) 
        {
            if (!(lm_igu_sb->status & LM_IGU_STATUS_PF) && !(lm_igu_sb->status & LM_IGU_STATUS_BUSY)) 
            {
                available_igu_sbs++;
            }            
        }
    }
    return available_igu_sbs;
}

lm_status_t lm_pf_update_vf_default_vlan(IN struct _lm_device_t    *pdev, IN struct _lm_vf_info_t * vf_info,
                              IN const u16_t            silent_vlan_value,
                              IN const u16_t            silent_vlan_mask,
                              IN const u8_t             silent_vlan_removal_flg,
                              IN const u8_t             silent_vlan_change_flg,
                              IN const u16_t            default_vlan,
                              IN const u8_t             default_vlan_enable_flg,
                              IN const u8_t             default_vlan_change_flg)
{
    struct client_update_ramrod_data * client_update_data_virt = NULL;
    lm_status_t                        lm_status               = LM_STATUS_FAILURE;    
    u32_t                              vf_cid_of_pf            = 0;
    u8_t                               type                    = 0;
    u8_t                               q_idx                   = 0;


    for (q_idx = 0; q_idx < vf_info->vf_si_num_of_active_q; q_idx++) {
        client_update_data_virt = pdev->client_info[LM_SW_VF_CLI_ID(vf_info, q_idx)].update.data_virt;
        if CHK_NULL(client_update_data_virt)
        {
            DbgBreak();
            return LM_STATUS_FAILURE;
        }
        mm_mem_zero((void *) client_update_data_virt , sizeof(struct client_update_ramrod_data));
    
        MM_ACQUIRE_ETH_CON_LOCK(pdev);
    
        DbgBreakIf( LM_CLI_UPDATE_NOT_USED != pdev->client_info[LM_SW_VF_CLI_ID(vf_info, q_idx)].update.state);
    
        pdev->client_info[LM_SW_VF_CLI_ID(vf_info, q_idx)].update.state = LM_CLI_UPDATE_USED;
    
        client_update_data_virt->client_id  = LM_FW_VF_CLI_ID(vf_info, q_idx);
        client_update_data_virt->func_id    = 8 + vf_info->abs_vf_id;
    
        client_update_data_virt->silent_vlan_value          = mm_cpu_to_le16(silent_vlan_value);
        client_update_data_virt->silent_vlan_mask           = mm_cpu_to_le16(silent_vlan_mask);
        client_update_data_virt->silent_vlan_removal_flg    = silent_vlan_removal_flg;
        client_update_data_virt->silent_vlan_change_flg     = silent_vlan_change_flg;
    
        client_update_data_virt->default_vlan               = mm_cpu_to_le16(default_vlan);
        client_update_data_virt->default_vlan_enable_flg    = default_vlan_enable_flg;
        client_update_data_virt->default_vlan_change_flg    = default_vlan_change_flg;

        client_update_data_virt->refuse_outband_vlan_flg        = 0;
        client_update_data_virt->refuse_outband_vlan_change_flg = 0;
    
        vf_cid_of_pf = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_idx);
        type = (ETH_CONNECTION_TYPE | ((8 + vf_info->abs_vf_id) << SPE_HDR_T_FUNCTION_ID_SHIFT));
        
        lm_status = lm_sq_post(pdev, 
                               vf_cid_of_pf, 
                               RAMROD_CMD_ID_ETH_CLIENT_UPDATE,
                               CMD_PRIORITY_MEDIUM, 
                               type, 
                               pdev->client_info[LM_SW_VF_CLI_ID(vf_info, q_idx)].update.data_phys.as_u64);
    
    
        MM_RELEASE_ETH_CON_LOCK(pdev);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    
        lm_status = lm_wait_state_change(pdev, &pdev->client_info[LM_SW_VF_CLI_ID(vf_info, q_idx)].update.state, LM_CLI_UPDATE_RECV);
    
        pdev->client_info[LM_SW_VF_CLI_ID(vf_info, q_idx)].update.state = LM_CLI_UPDATE_NOT_USED;
    }

    return lm_status;
}

lm_status_t lm_pf_update_vf_ndsb(IN struct _lm_device_t     *pdev, 
                                  IN struct _lm_vf_info_t   *vf_info,
                                  IN u8_t                   relative_in_vf_ndsb,
                                  IN u16_t                  interrupt_mod_level)
{
    lm_status_t lm_status   = LM_STATUS_SUCCESS;    
    u8_t        dhc_timeout, hc_rx_timeout, hc_tx_timeout;
    lm_int_coalesing_info* 
                ic          = &pdev->vars.int_coal;
    u32_t       rx_coal_usec,tx_coal_usec;


    switch (interrupt_mod_level) 
    {
        case VPORT_INT_MOD_UNDEFINED:
            dhc_timeout = 0;
            hc_rx_timeout = (u8_t)(ic->hc_usec_u_sb[HC_INDEX_VF_ETH_RX_CQ_CONS] / HC_TIMEOUT_RESOLUTION_IN_US);
            DbgBreakIf(HC_INDEX_VF_ETH_TX_CQ_CONS < HC_USTORM_SB_NUM_INDICES);      
            hc_tx_timeout = (u8_t)(ic->hc_usec_c_sb[HC_INDEX_VF_ETH_TX_CQ_CONS - HC_USTORM_SB_NUM_INDICES] / HC_TIMEOUT_RESOLUTION_IN_US);
            break;
        case VPORT_INT_MOD_ADAPTIVE:
            dhc_timeout = (u8_t)pdev->params.hc_timeout0[SM_RX_ID][HC_INDEX_VF_ETH_RX_CQ_CONS];
            hc_rx_timeout = (u8_t)(ic->hc_usec_u_sb[HC_INDEX_VF_ETH_RX_CQ_CONS] / HC_TIMEOUT_RESOLUTION_IN_US);      
            hc_tx_timeout = (u8_t)(ic->hc_usec_c_sb[HC_INDEX_VF_ETH_TX_CQ_CONS - HC_USTORM_SB_NUM_INDICES] / HC_TIMEOUT_RESOLUTION_IN_US);
            break;
        case VPORT_INT_MOD_OFF:
            dhc_timeout = 0;
            hc_rx_timeout = 0;      
            hc_tx_timeout = 0;
            break;
        case VPORT_INT_MOD_LOW:
            dhc_timeout = 0;
            rx_coal_usec = 1000000 / pdev->params.vf_int_per_sec_rx[LM_VF_INT_LOW_IDX];
            tx_coal_usec = 1000000 / pdev->params.vf_int_per_sec_tx[LM_VF_INT_LOW_IDX];
            hc_rx_timeout = (u8_t)(rx_coal_usec / HC_TIMEOUT_RESOLUTION_IN_US);      
            hc_tx_timeout = (u8_t)(rx_coal_usec / HC_TIMEOUT_RESOLUTION_IN_US);
            break;
        case VPORT_INT_MOD_MEDIUM:
            dhc_timeout = 0;
            rx_coal_usec = 1000000 / pdev->params.vf_int_per_sec_rx[LM_VF_INT_MEDIUM_IDX];
            tx_coal_usec = 1000000 / pdev->params.vf_int_per_sec_tx[LM_VF_INT_MEDIUM_IDX];
            hc_rx_timeout = (u8_t)(rx_coal_usec / HC_TIMEOUT_RESOLUTION_IN_US);      
            hc_tx_timeout = (u8_t)(rx_coal_usec / HC_TIMEOUT_RESOLUTION_IN_US);
            break;
        case VPORT_INT_MOD_HIGH:
            dhc_timeout = 0;
            rx_coal_usec = 1000000 / pdev->params.vf_int_per_sec_rx[LM_VF_INT_HIGH_IDX];
            tx_coal_usec = 1000000 / pdev->params.vf_int_per_sec_tx[LM_VF_INT_HIGH_IDX];
            hc_rx_timeout = (u8_t)(rx_coal_usec / HC_TIMEOUT_RESOLUTION_IN_US);      
            hc_tx_timeout = (u8_t)(rx_coal_usec / HC_TIMEOUT_RESOLUTION_IN_US);
            break;
        default:
            lm_status = LM_STATUS_INVALID_PARAMETER;
            DbgBreak();
            break;
    }
    if (lm_status == LM_STATUS_SUCCESS) 
    {
        u8_t dhc_enable;
        u8_t timeout;
        u32_t index;
        
        if (dhc_timeout) 
        {
            dhc_enable = TRUE;
            timeout = dhc_timeout;
            REG_WR(PFDEV(pdev), CSEM_REG_FAST_MEMORY + CSTORM_BYTE_COUNTER_OFFSET(LM_FW_VF_DHC_QZONE_ID(vf_info, relative_in_vf_ndsb), HC_INDEX_VF_ETH_RX_CQ_CONS), 0);
        }
        else
        {
            dhc_enable = FALSE;
            timeout = hc_rx_timeout;
        }
        lm_setup_ndsb_index(pdev, LM_SW_VF_SB_ID(vf_info,relative_in_vf_ndsb), HC_INDEX_VF_ETH_RX_CQ_CONS, SM_RX_ID, timeout, dhc_enable);
        lm_setup_ndsb_index(pdev, LM_SW_VF_SB_ID(vf_info,relative_in_vf_ndsb), HC_INDEX_VF_ETH_TX_CQ_CONS, SM_TX_ID, hc_tx_timeout, FALSE);
        for (index = 0; index < sizeof(struct hc_status_block_data_e2)/sizeof(u32_t); index++) {
            LM_INTMEM_WRITE32(pdev, CSTORM_STATUS_BLOCK_DATA_OFFSET(LM_FW_VF_SB_ID(vf_info, relative_in_vf_ndsb)) + sizeof(u32_t)*index,
                              *((u32_t*)(&pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,relative_in_vf_ndsb)].hc_status_block_data.e2_sb_data) + index), BAR_CSTRORM_INTMEM);
        }
    }
    return lm_status;
}

lm_status_t lm_pf_update_vf_ndsbs(IN struct _lm_device_t    *pdev, 
                                  IN struct _lm_vf_info_t   *vf_info,
                                  IN u16_t                  interrupt_mod_level)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;    
    u8_t q_idx = 0;
    u8_t  is_hc_available_on_host;
    u16_t client_interrupt_mod_level;
    if (pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC) 
    {
        is_hc_available_on_host = TRUE;
    }
    else
    {
        is_hc_available_on_host = FALSE;
    }
    
    switch (interrupt_mod_level) 
    {
        case VPORT_INT_MOD_OFF:
            break;
        case VPORT_INT_MOD_UNDEFINED:
            if (is_hc_available_on_host) 
            {
                interrupt_mod_level = VPORT_INT_MOD_ADAPTIVE;
            }
        case VPORT_INT_MOD_ADAPTIVE:
        case VPORT_INT_MOD_LOW:
        case VPORT_INT_MOD_MEDIUM:
        case VPORT_INT_MOD_HIGH:
            if (!is_hc_available_on_host) 
            {
                interrupt_mod_level = VPORT_INT_MOD_OFF;
            }
            break;
        default:
            lm_status = LM_STATUS_INVALID_PARAMETER;
            DbgBreak();
            break;
    }

    if (lm_status != LM_STATUS_SUCCESS) 
    {
        return lm_status;
    }
    
    vf_info->current_interrupr_moderation = interrupt_mod_level;
    for (q_idx = 0; q_idx < vf_info->vf_si_num_of_active_q; q_idx++) 
    {
        client_interrupt_mod_level = interrupt_mod_level;
        if ((interrupt_mod_level == VPORT_INT_MOD_ADAPTIVE) && !pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_idx)].client_init_data_virt->init_data.rx.enable_dynamic_hc) 
        {
            client_interrupt_mod_level = VPORT_INT_MOD_UNDEFINED;
        }
        lm_pf_update_vf_ndsb(pdev, vf_info, q_idx, client_interrupt_mod_level);
    }
    
    return lm_status;
}
#endif //VF_INVOLVED
