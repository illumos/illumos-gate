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
 *      This file contains functions having to do with Device info, licensing
 *      and Bandwidth Allocation
 *
 ******************************************************************************/

#include "lm5710.h"

unsigned long log2_align(unsigned long n);

u64_t lm_get_timestamp_of_recent_cid_recycling(struct _lm_device_t *pdev)
{
    return pdev->vars.last_recycling_timestamp;
}

u32_t lm_get_max_supported_toe_cons(struct _lm_device_t *pdev)
{
    if ( CHK_NULL(pdev) )
    {
        return 0;
    }
    return pdev->params.max_supported_toe_cons;
}

u8_t lm_get_toe_rss_possibility(struct _lm_device_t *pdev)
{
    if ( CHK_NULL(pdev) )
    {
        return 0;
    }
    return (pdev->params.l4_rss_is_possible != L4_RSS_DISABLED);
}

/*******************************************************************************
 * Description:
 *     reads iscsi_boot info block from shmem
 * Return:
 *     lm_status
 ******************************************************************************/
lm_status_t lm_get_iscsi_boot_info_block( struct _lm_device_t *pdev, struct _iscsi_info_block_hdr_t* iscsi_info_block_hdr_ptr )
{
    u32_t           val                = 0;
    u32_t           offset             = 0;
    const u8_t      func_mb_id         = FUNC_MAILBOX_ID(pdev);

    // dummy variables so we have convenience way to know the shmem offsets
                                               // This is a pointer so it doesn't load the stack.
    // If we delete these lines we won't have shmem_region_t symbols
    shmem_region_t*    shmem_region_dummy    = NULL;
    shmem2_region_t*   shmem2_region_dummy   = NULL;
    shared_hw_cfg_t*   shared_hw_cfg_dummy   = NULL;
    port_hw_cfg_t*     port_hw_cfg_dummy     = NULL;
    shared_feat_cfg_t* shared_feat_cfg_dummy = NULL;
    port_feat_cfg_t*   port_feat_cfg_dummy   = NULL;
    mf_cfg_t*          mf_cfg_dummy          = NULL;

    UNREFERENCED_PARAMETER_(shmem_region_dummy);
    UNREFERENCED_PARAMETER_(shmem2_region_dummy);
    UNREFERENCED_PARAMETER_(shared_hw_cfg_dummy);
    UNREFERENCED_PARAMETER_(port_hw_cfg_dummy);
    UNREFERENCED_PARAMETER_(shared_feat_cfg_dummy);
    UNREFERENCED_PARAMETER_(port_feat_cfg_dummy);
    UNREFERENCED_PARAMETER_(mf_cfg_dummy);

    if ( CHK_NULL( iscsi_info_block_hdr_ptr ) )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    if (pdev->hw_info.mcp_detected == 1)
    {
        offset = OFFSETOF(shmem_region_t,func_mb[func_mb_id].iscsi_boot_signature);
        LM_SHMEM_READ(pdev, offset, &val );
        iscsi_info_block_hdr_ptr->signature = val ;
        // only for debugging
        offset = OFFSETOF(shmem_region_t,func_mb[func_mb_id].iscsi_boot_block_offset);
        LM_SHMEM_READ(pdev, offset, &val );
        if (val == UEFI_BOOT_SIGNATURE)
        {
            SET_FLAGS(iscsi_info_block_hdr_ptr->boot_flags, BOOT_INFO_FLAGS_UEFI_BOOT );
        }
        else
        {
            RESET_FLAGS(iscsi_info_block_hdr_ptr->boot_flags, BOOT_INFO_FLAGS_UEFI_BOOT );
        }
    }
    else
    {
        // If mcp is detected the shmenm is not initialized and
        iscsi_info_block_hdr_ptr->signature = 0;
    }
    return LM_STATUS_SUCCESS ;
}

lm_status_t
lm_get_ibft_physical_addr_for_efi(
    struct _lm_device_t *pdev, u32_t *phy_hi, u32_t *phy_lo
    )
{
    u32_t           offset             = 0;
    u32_t           val                = 0;
    const u8_t      func_mb_id         = FUNC_MAILBOX_ID(pdev);

    if (pdev->hw_info.mcp_detected == 1)
    {
        offset = OFFSETOF(shmem_region_t,func_mb[func_mb_id].iscsi_boot_signature);
        LM_SHMEM_READ(pdev, offset, &val );
        //iscsi_info_block_hdr_ptr->signature = val ;
        // only for debugging
        offset = OFFSETOF(shmem_region_t,func_mb[func_mb_id].iscsi_boot_block_offset);
        LM_SHMEM_READ(pdev, offset, &val );
        if (val == UEFI_BOOT_SIGNATURE)
        {
            offset = OFFSETOF(shmem2_region_t,ibft_host_addr);
            LM_SHMEM2_READ(pdev, offset , &val);
            *phy_lo = val;
            *phy_hi = 0;

            return LM_STATUS_SUCCESS;
        }
    }
    return LM_STATUS_FAILURE;
}
lm_status_t
lm_get_sriov_info(lm_device_t *pdev)
{
    lm_status_t rc = LM_STATUS_SUCCESS;
    u32_t val;
    if (!CHIP_IS_E1x(pdev)) {
        /* get bars... */
#ifdef VF_INVOLVED
        rc = mm_get_sriov_info(pdev, &pdev->hw_info.sriov_info);
        if (rc != LM_STATUS_SUCCESS) {
            return rc;
        }
#endif

#ifdef __LINUX
        lm_set_virt_mode(pdev, DEVICE_TYPE_PF, (pdev->hw_info.sriov_info.total_vfs? VT_BASIC_VF : VT_NONE));
#elif defined(_VBD_CMD_)
        lm_set_virt_mode(pdev, DEVICE_TYPE_PF, (pdev->hw_info.sriov_info.total_vfs? VT_CHANNEL_VF : VT_NONE));
#endif
        /* Since registers from 0x000-0x7ff are spilt across functions, each PF will have  the same location for the same 4 bits*/
        val = REG_RD(pdev, PCICFG_OFFSET + GRC_CONFIG_REG_PF_INIT_VF);
        pdev->hw_info.sriov_info.first_vf_in_pf = ((val & GRC_CR_PF_INIT_VF_PF_FIRST_VF_NUM_MASK) * 8) - E2_MAX_NUM_OF_VFS*PATH_ID(pdev);
        DbgMessage(pdev, WARN, "First VF in PF = %d\n", pdev->hw_info.sriov_info.first_vf_in_pf);
    }
    return rc;
}


static void lm_print_func_info(lm_device_t *pdev)
{
    DbgMessage(pdev, WARN, "lm_get_shmem_info: FUNC_ID: %d\n", FUNC_ID(pdev));
    DbgMessage(pdev, WARN, "lm_get_shmem_info: PCI_FUNC_ID: %d\n", ABS_FUNC_ID(pdev));
    DbgMessage(pdev, WARN, "lm_get_shmem_info: PORT_ID: %d\n", PORT_ID(pdev));

    if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
    {
        DbgMessage(pdev, WARN, "lm_get_shmem_info: ETH_PORT_ID: %d\n", PATH_ID(pdev) + 2*PORT_ID(pdev));
    }
    else
    {
        DbgMessage(pdev, WARN, "lm_get_shmem_info: ETH_PORT_ID: %d\n", PATH_ID(pdev) + PORT_ID(pdev));
    }

    DbgMessage(pdev, WARN, "lm_get_shmem_info: PATH_ID: %d\n", PATH_ID(pdev));
    DbgMessage(pdev, WARN, "lm_get_shmem_info: VNIC_ID: %d\n", VNIC_ID(pdev));
    DbgMessage(pdev, WARN, "lm_get_shmem_info: FUNC_MAILBOX_ID: %d\n", FUNC_MAILBOX_ID(pdev));

}


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_get_function_num(lm_device_t *pdev)
{
    u32_t val = 0;
    /* read the me register to get function number. */
    /* Me register: holds the relative-function num + absolute-function num,
     * absolute-function-num appears only from E2 and above. Before that these bits
     * always contained zero, therefore we can't take as is. */
    val = REG_RD(pdev, BAR_ME_REGISTER);
    pdev->params.pfunc_rel = (u8_t)((val & ME_REG_PF_NUM) >> ME_REG_PF_NUM_SHIFT);
    pdev->params.path_id = (u8_t)((val & ME_REG_ABS_PF_NUM) >> ME_REG_ABS_PF_NUM_SHIFT) & 1;

    if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
    {
        pdev->params.pfunc_abs = (pdev->params.pfunc_rel << 1) | pdev->params.path_id;
    }
    else
    {
        pdev->params.pfunc_abs = pdev->params.pfunc_rel | pdev->params.path_id;
    }
    pdev->params.pfunc_mb_id = FUNC_MAILBOX_ID(pdev);

    DbgMessage(pdev, INFORM , "relative function %d absolute function %d\n", pdev->params.pfunc_rel, pdev->params.pfunc_abs);

    lm_print_func_info(pdev);
    return LM_STATUS_SUCCESS;
}


// reads max_payload_size & max_read_req_size from pci config space
lm_status_t lm_get_pcicfg_mps_mrrs(lm_device_t * pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t       val       = 0;

    /* get max payload size and max read size we need it for pxp configuration
    in the real chip it should be done by the MCP.*/
    lm_status = mm_read_pci(pdev, PCICFG_DEVICE_CONTROL, &val);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    // bit 5-7
    pdev->hw_info.max_payload_size = (val & 0xe0)>>5;
    // bit 12-14
    pdev->hw_info.max_read_req_size = (val & 0x7000)>>12;
    DbgMessage(pdev, INFORMi, "reg 0xd8 0x%x \n max_payload %d max_read_req %d \n",
                val,pdev->hw_info.max_payload_size,pdev->hw_info.max_read_req_size);

    return lm_status ;
}

lm_status_t lm_get_pcicfg_info(lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t val;
    /* Get PCI device and vendor id. (need to be read from parent */
    if (IS_PFDEV(pdev) || IS_CHANNEL_VFDEV(pdev))
    {
        lm_status = mm_read_pci(pdev, PCICFG_VENDOR_ID_OFFSET, &val);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
        if (val != 0xFFFFFFFF)
        {
            pdev->hw_info.vid = (u16_t) val;
            pdev->hw_info.did = (u16_t) (val >> 16);
        }
        else if (IS_SW_CHANNEL_VIRT_MODE(pdev))
        {
            pdev->hw_info.vid = 0x14E4;
            pdev->hw_info.did = 0x166F;
        }
        DbgMessage(pdev, INFORMi, "vid 0x%x\n", pdev->hw_info.vid);
        DbgMessage(pdev, INFORMi, "did 0x%x\n", pdev->hw_info.did);
    }
    else
    {
        DbgMessage(pdev, WARN, "vid&did for VBD VF will be known later\n"); /*Must be known earlier*/
    }
    /* Get subsystem and subvendor id. */
    lm_status = mm_read_pci(pdev, PCICFG_SUBSYSTEM_VENDOR_ID_OFFSET, &val);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.svid = (u16_t) val;
    DbgMessage(pdev, INFORMi, "svid 0x%x\n", pdev->hw_info.svid);
    pdev->hw_info.ssid = (u16_t) (val >> 16);
    DbgMessage(pdev, INFORMi, "ssid 0x%x\n", pdev->hw_info.ssid);

    /* Get IRQ, and interrupt pin. */
    lm_status = mm_read_pci(pdev, PCICFG_INT_LINE, &val);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    pdev->hw_info.irq = (u8_t) val;
    DbgMessage(pdev, INFORMi, "IRQ 0x%x\n", pdev->hw_info.irq);
    pdev->hw_info.int_pin = (u8_t) (val >> 8);
    DbgMessage(pdev, INFORMi, "Int pin 0x%x\n", pdev->hw_info.int_pin);

    /* Get cache line size. */
    lm_status = mm_read_pci(pdev, PCICFG_CACHE_LINE_SIZE, &val);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.cache_line_size = (u8_t) val;
    DbgMessage(pdev, INFORMi, "Cache line size 0x%x\n", (u8_t) val);
    pdev->hw_info.latency_timer = (u8_t) (val >> 8);
    DbgMessage(pdev, INFORMi, "Latency timer 0x%x\n", (u8_t) (val >> 8));

    /* Get PCI revision id. */
    lm_status = mm_read_pci(pdev, PCICFG_REVISION_ID_OFFSET, &val);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    pdev->hw_info.rev_id = (u8_t) val;
    DbgMessage(pdev, INFORMi, "Revision id 0x%x\n", pdev->hw_info.rev_id);

    /* Get PCI-E speed*/
    /* only for PF */
    if (IS_PFDEV(pdev))
    {
        lm_status = mm_read_pci(pdev, PCICFG_LINK_CONTROL, &val);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        /* bit 20-25 */
        pdev->hw_info.pcie_lane_width = (val & 0x3f00000) >> 20;
        DbgMessage(pdev, INFORMi, "pcie_lane_width 0x%x\n", pdev->hw_info.pcie_lane_width);
        /* bit 16 - 19 */
        pdev->hw_info.pcie_lane_speed = (val & 0xf0000) >> 16;
        DbgMessage(pdev, INFORMi, "pcie_lane_speed 0x%x\n", pdev->hw_info.pcie_lane_speed);

        lm_status = lm_get_pcicfg_mps_mrrs(pdev);
    }

    // CQ61532 - Fan Failure test fails when stop the fan for more than 10 seconds and reboot.
    // Actually most chances we won't get until here if the value is error = we might read other registers before that will hang the machine in Windows
    // Hopefully this read will help with other LM drivers
    // anyway, we'll fail the bind for that...
    if (GET_FLAGS(pdev->hw_info.rev_id,PCICFG_REVESION_ID_MASK) == PCICFG_REVESION_ID_ERROR_VAL)
    {
        return LM_STATUS_FAILURE;
    }

    return lm_status;
}
/**
 * This function reads bar offset from PCI configuration
 * header.
 *
 * @param _pdev
 * @param bar_num Bar index: BAR_0 or BAR_1 or BAR_2
 * @param bar_addr Output value (bar offset).
 *
 * @return LM_STATUS_SUCCESS if bar offset has been read
 *         successfully.
 */
static __inline lm_status_t lm_get_bar_offset_direct(
    IN   struct _lm_device_t * pdev,
    IN   u8_t                  bar_num,   /* Bar index: BAR_0 or BAR_1 or BAR_2 */
    OUT lm_address_t         * bar_addr )
{
    u32_t pci_reg, val;
    lm_status_t lm_status;
    /* Get BARs addresses. */
    switch (bar_num) {
    case BAR_0:
        pci_reg = PCICFG_BAR_1_LOW;
        break;
    case BAR_1:
        pci_reg = PCICFG_BAR_1_LOW + 8;
        break;
    case BAR_2:
        pci_reg = PCICFG_BAR_1_LOW + 16;
        break;
    default:
        DbgMessage(pdev, FATAL, "Unsupported bar index: %d\n", bar_num);
        DbgBreakIfAll(1);
        return LM_STATUS_INVALID_PARAMETER;
    }
    lm_status = mm_read_pci(pdev, pci_reg, &val);
    if(lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }
    bar_addr->as_u32.low = val & 0xfffffff0;;
    DbgMessage(pdev, INFORMi, "BAR %d low 0x%x\n", bar_num,
                bar_addr->as_u32.low);
    pci_reg += 4; /* sizeof configuration space bar address register */
    lm_status = mm_read_pci(pdev, pci_reg, &val);
    if(lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }
    bar_addr->as_u32.high = val;
    DbgMessage(pdev, INFORMi, "BAR %d high 0x%x\n", bar_num,
                bar_addr->as_u32.high);
    return LM_STATUS_SUCCESS;
}

static __inline lm_status_t lm_get_bar_size_direct (
    IN  lm_device_t *pdev,
    IN  u8_t bar_num,
    OUT  u32_t * val_p)
{
    u32_t bar_address = 0;
    u32_t bar_size;
    switch (bar_num) {
    case BAR_0:
        bar_address = GRC_CONFIG_2_SIZE_REG;
        break;
    case BAR_1:
        bar_address = GRC_BAR2_CONFIG;
        break;
    case BAR_2:
        bar_address = GRC_BAR3_CONFIG;
        break;
    default:
        DbgMessage(pdev, FATAL, "Invalid Bar Num\n");
        return LM_STATUS_INVALID_PARAMETER;
    }
    lm_reg_rd_ind(pdev,PCICFG_OFFSET + bar_address,&bar_size);
    /*extract only bar size*/
    ASSERT_STATIC(PCI_CONFIG_2_BAR1_SIZE == PCI_CONFIG_2_BAR2_SIZE);
    ASSERT_STATIC(PCI_CONFIG_2_BAR2_SIZE == PCI_CONFIG_2_BAR3_SIZE);

    bar_size = (bar_size & PCI_CONFIG_2_BAR1_SIZE);
    if (bar_size == 0)
    {
        /*bar size disabled*/
        return LM_STATUS_FAILURE;
    }
    else
    {
        /*bit 1 stand for 64K each bit multiply it by two */
        *val_p = (0x40 << ((bar_size - 1)))*0x400;
    }

    return LM_STATUS_SUCCESS;
}
/* init pdev->hw_info with data from pcicfg */
lm_status_t lm_get_bars_info(lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t bar_map_size = 0;
    u8_t i;

    /* Get BARs addresses. */
    for (i = 0; i < ARRSIZE(pdev->hw_info.mem_base); i++)
    {
        lm_status = mm_get_bar_offset(pdev, i, &pdev->hw_info.mem_base[i]);
        DbgMessage(pdev, INFORMi, "Bar_Offset=0x%x\n", pdev->hw_info.mem_base[i]);

        if(lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
        if(pdev->hw_info.mem_base[i].as_u64 == 0)
        {
            DbgMessage(pdev, WARNi, "BAR %d IS NOT PRESENT\n", i);
            if(i==0)
            {
                DbgBreakMsg("BAR 0 must be present\n");
            }
        }
    }
    /* TBA: review two intializations done in Teton here (are they needed? are they part of "get_bars_info"):
    - Enable PCI bus master....
    - Configure byte swap and enable write to the reg_window registers
    */
    for (i = 0; i < MAX_NUM_BAR; i++)
    {
        if(pdev->hw_info.mem_base[i].as_u64 == 0)
        {
            continue;
        }

        /* get bar i size*/
        lm_status = mm_get_bar_size(pdev, i, &(pdev->hw_info.bar_size[i]));

        if ( lm_status != LM_STATUS_SUCCESS )
        {
            return lm_status;
        }
        DbgMessage(pdev, INFORMi, "bar %d size 0x%x\n", i, pdev->hw_info.bar_size[i]);
        /* Change in BAR1
         * The function will map in case of BAR1 only the ETH cid doorbell space to a virtual address.
         * (Map from BAR1 base address, to BAR1 base address plus MAX_ETH_CONS* LM_PAGE_SIZE).
        */
        if (BAR_1 == i )
        {
            if (IS_PFDEV(pdev))
            { //TODO Revise it
#ifdef VF_INVOLVED
                bar_map_size = pdev->hw_info.bar_size[i];
#else
                bar_map_size = LM_DQ_CID_SIZE * MAX_ETH_CONS;
#endif
            }
            else
            {
                bar_map_size = LM_DQ_CID_SIZE;
            }
#ifndef VF_INVOLVED
            DbgBreakIf(bar_map_size >= pdev->hw_info.bar_size[i]);
#endif
        }
        else
        {
            bar_map_size = pdev->hw_info.bar_size[i];
        }
        /* Map bar i to system address space. If not mapped already. */
        if(lm_is_function_after_flr(pdev) ||
#ifdef VF_INVOLVED
           lm_is_function_after_flr(PFDEV(pdev)) ||
#endif
           (pdev->vars.mapped_bar_addr[i] == NULL))
        {
                pdev->vars.mapped_bar_addr[i] = NULL;
                pdev->vars.mapped_bar_addr[i] = mm_map_io_base(
                        pdev,
                        pdev->hw_info.mem_base[i],
                        bar_map_size,
                        i);
                if(pdev->vars.mapped_bar_addr[i] == NULL)
                {
                    DbgMessage(pdev, FATAL, "bar %d map io failed\n", i);
                    return LM_STATUS_FAILURE;
                }
                else
                {
                    DbgMessage(pdev, INFORMi, "mem_base[%d]=%p size=0x%x\n", i, pdev->vars.mapped_bar_addr[i], pdev->hw_info.bar_size[i]);
                }
        }
    }
    /* Now that the bars are mapped, we need to enable target read + write and master-enable,
     * we can't do this before bars are mapped, but we need to do this before we start any chip
     * initializations... */
#if defined(__LINUX) || defined(_VBD_)
    if (IS_PFDEV(pdev))
    {
        pdev->hw_info.pcie_caps_offset = mm_get_cap_offset(pdev, PCI_CAP_PCIE);
        if (pdev->hw_info.pcie_caps_offset != 0 && pdev->hw_info.pcie_caps_offset != 0xFFFFFFFF)
        {
            mm_read_pci(pdev, pdev->hw_info.pcie_caps_offset + PCIE_DEV_CAPS, &pdev->hw_info.pcie_dev_capabilities);

            DbgMessage(pdev, WARN,"Device Capability of PCIe caps is %x\n",pdev->hw_info.pcie_dev_capabilities);

            if (pdev->hw_info.pcie_dev_capabilities)
            {
                if (pdev->hw_info.pcie_dev_capabilities & PCIE_DEV_CAPS_FLR_CAPABILITY)
                {
                    pdev->hw_info.flr_capable = TRUE;
                }
                else
                {
                    pdev->hw_info.flr_capable = FALSE; /*Not trusted for PCI_CFG accesible via hypervisor*/
                }
            }
            else
            {
                pdev->hw_info.pci_cfg_trust = PCI_CFG_NOT_TRUSTED;
            }
        }
        else
        {
            pdev->hw_info.pci_cfg_trust = PCI_CFG_NOT_TRUSTED;
        }

        if (!lm_is_function_after_flr(pdev))
        {
            pdev->hw_info.grc_didvid = REG_RD(pdev, (PCICFG_OFFSET + PCICFG_VENDOR_ID_OFFSET));
            lm_status = mm_read_pci(pdev, PCICFG_VENDOR_ID_OFFSET, &pdev->hw_info.pci_cfg_didvid);
            if (lm_status == LM_STATUS_SUCCESS)
            {
                if (pdev->hw_info.grc_didvid != pdev->hw_info.pci_cfg_didvid)
                {
                    pdev->hw_info.flr_capable = TRUE;
                    pdev->params.is_flr = TRUE;
                }
            }
        }
    }
#endif
    if (lm_is_function_after_flr(pdev))
    {
        u32_t m_e,tr_e,tw_e;
        u32_t i_cycles;
        REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_TARGET_READ, 1);
        for (i_cycles = 0; i_cycles < 1000; i_cycles++)
        {
            mm_wait(pdev,999);
        }
        tr_e = REG_RD(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_TARGET_READ);
        tw_e = REG_RD(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_TARGET_WRITE);
        m_e = REG_RD(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER);
        DbgMessage(pdev, INFORM, "M:0x%x, TR:0x%x, TW:0x%x\n",m_e,tr_e,tw_e);
        if (tw_e != 0x1)
        {
            DbgBreakMsg("BAR 0 must be present\n");
            return LM_STATUS_FAILURE;
        }
    }
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_get_chip_id_and_mode(lm_device_t *pdev)
{
    u32_t val;
    u32_t chip_rev;

    /* Get the chip revision id and number. */
    /* chip num:16-31, rev:12-15, metal:4-11, bond_id:0-3 */
    val=REG_RD(PFDEV(pdev),MISC_REG_CHIP_NUM);
    CHIP_NUM_SET(pdev->hw_info.chip_id,val);

    /* If OTP process was done on the device, change chip number to 57811 */
    val=REG_RD(PFDEV(pdev),MISC_REG_CHIP_TYPE);
    if (val & CHIP_OPT_MISC_DO_BIT)
    {
         switch (pdev->hw_info.chip_id)
         {
            case CHIP_NUM_57810:
                pdev->hw_info.chip_id = CHIP_NUM_57811;
                break;
            case CHIP_NUM_57810_MF:
               pdev->hw_info.chip_id = CHIP_NUM_57811_MF;
                break;
            default:
                DbgMessage(pdev, FATAL, "Un-supported chip id for OTP: %d\n", pdev->hw_info.chip_id);
                DbgBreakIfAll(1);
                return LM_STATUS_FAILURE;
         }
    }

    val=REG_RD(PFDEV(pdev),MISC_REG_CHIP_REV);
    // the chip rev is realy ASIC when it < 5
    // when it > 5 odd mean FPGA even EMUL.
    chip_rev = (val & 0xF)<<CHIP_REV_SHIFT;
    pdev->hw_info.chip_id |= chip_rev;

    if(chip_rev <= CHIP_REV_ASIC_MAX)
    {
        pdev->vars.clk_factor = 1;
    }
    else if(chip_rev & CHIP_REV_SIM_IS_FPGA)
    {
        pdev->vars.clk_factor = LM_FPGA_FACTOR;
        DbgMessage(pdev, INFORMi, "FPGA: forcing MPS from %d to 0.\n", pdev->hw_info.max_payload_size);
        pdev->hw_info.max_payload_size = 0;
    }
    else
    {
        pdev->vars.clk_factor = LM_EMUL_FACTOR;
    }

    val=REG_RD(PFDEV(pdev),MISC_REG_CHIP_METAL);
    pdev->hw_info.chip_id |= (val & 0xff) << 4;
    val=REG_RD(PFDEV(pdev),MISC_REG_BOND_ID);
    pdev->hw_info.chip_id |= (val & 0xf);
    DbgMessage(pdev, INFORMi , "chip id 0x%x\n", pdev->hw_info.chip_id);
    /* Read silent revision */
    val=REG_RD(PFDEV(pdev),MISC_REG_CHIP_TEST_REG);
    pdev->hw_info.silent_chip_rev = (val & 0xff);
    DbgMessage(pdev, INFORMi , "silent chip rev 0x%x\n", pdev->hw_info.silent_chip_rev);
    if (!CHIP_IS_E1x(pdev))
    {
        /* Determine whether we are 2 port or 4 port mode */
        /* read port4mode_en_ovwr[0];
         * b)     if 0  read port4mode_en (0  2-port; 1  4-port);
         * c)     if 1  read port4mode_en_ovwr[1] (0  2-port; 1  4-port);
         */
        val = REG_RD(PFDEV(pdev), MISC_REG_PORT4MODE_EN_OVWR);
        DbgMessage(pdev, WARN, "MISC_REG_PORT4MODE_EN_OVWR = %d\n", val);
        if ((val & 1) == 0)
        {
            val = REG_RD(PFDEV(pdev), MISC_REG_PORT4MODE_EN);
        }
        else
        {
            val = (val >> 1) & 1;
        }
        pdev->hw_info.chip_port_mode = val? LM_CHIP_PORT_MODE_4 : LM_CHIP_PORT_MODE_2;
        DbgMessage(pdev, WARN, "chip_port_mode %s\n", (pdev->hw_info.chip_port_mode == LM_CHIP_PORT_MODE_4 )? "4_PORT" : "2_PORT");
    }
    else
    {
        pdev->hw_info.chip_port_mode = LM_CHIP_PORT_MODE_NONE; /* N/A */
        DbgMessage(pdev, WARN, "chip_port_mode NONE\n");
    }
    return LM_STATUS_SUCCESS;
}
static void lm_get_igu_cam_info(lm_device_t *pdev)
{
    lm_intr_blk_info_t *blk_info = &pdev->hw_info.intr_blk_info;
    u8_t igu_test_vectors = FALSE;
    #define IGU_CAM_VFID_MATCH(pdev, igu_fid) (!(igu_fid & IGU_FID_ENCODE_IS_PF) && ((igu_fid & IGU_FID_VF_NUM_MASK) == ABS_VFID(pdev)))
    #define IGU_CAM_PFID_MATCH(pdev, igu_fid) ((igu_fid & IGU_FID_ENCODE_IS_PF) && ((igu_fid & IGU_FID_PF_NUM_MASK) == FUNC_ID(pdev)))
    if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC)
    {
        blk_info->igu_info.igu_sb_cnt       = MAX_RSS_CHAINS;
        blk_info->igu_info.igu_u_sb_offset  = 0;
        if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_2)
        {
            blk_info->igu_info.igu_base_sb      = VNIC_ID(pdev) * MAX_RSS_CHAINS;
            blk_info->igu_info.igu_dsb_id       = MAX_VNIC_NUM * MAX_RSS_CHAINS + VNIC_ID(pdev);
        }
        else
        {
            blk_info->igu_info.igu_base_sb      = FUNC_ID(pdev) * MAX_RSS_CHAINS;
            blk_info->igu_info.igu_dsb_id       = MAX_VNIC_NUM * MAX_RSS_CHAINS + FUNC_ID(pdev);
        }
    }
    else
    {
        u8_t igu_sb_id;
        u8_t fid;
        u8_t vec;
        u8_t vf_id;
        u32_t val;
        u8_t current_pf_id = 0;
        u8_t recent_vf_id = 0xFF;
        blk_info->igu_info.igu_sb_cnt = 0;
        blk_info->igu_info.igu_test_sb_cnt = 0;
        blk_info->igu_info.igu_base_sb = 0xff;
        for (vf_id = 0; vf_id < E2_MAX_NUM_OF_VFS; vf_id++)
        {
            blk_info->igu_info.vf_igu_info[vf_id].igu_base_sb = 0xFF;
            blk_info->igu_info.vf_igu_info[vf_id].igu_sb_cnt = 0;
            blk_info->igu_info.vf_igu_info[vf_id].igu_test_sb_cnt = 0;
            blk_info->igu_info.vf_igu_info[vf_id].igu_test_mode = FALSE;
        }
        for (igu_sb_id = 0; igu_sb_id < IGU_REG_MAPPING_MEMORY_SIZE; igu_sb_id++ )
        {
            // mapping CAM; relevant for E2 operating mode only.
            // [0] - valid.
            // [6:1] - vector number;
            // [13:7] - FID (if VF - [13] = 0; [12:7] = VF number; if PF - [13] = 1; [12:9] = 0; [8:7] = PF number);
            lm_igu_block_t * lm_igu_sb = &IGU_SB(pdev,igu_sb_id);
            lm_igu_sb->block_dump = val = REG_RD(PFDEV(pdev), IGU_REG_MAPPING_MEMORY + 4*igu_sb_id);
            DbgMessage(pdev, WARN, "addr:0x%x IGU_CAM[%d]=%x\n",IGU_REG_MAPPING_MEMORY + 4*igu_sb_id, igu_sb_id, val);
            if (!(val & IGU_REG_MAPPING_MEMORY_VALID))
            {
                if (!IS_MULTI_VNIC(pdev) && (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_2))
                {
                    lm_igu_sb->status = LM_IGU_STATUS_AVAILABLE;
                }
                else if (current_pf_id == FUNC_ID(pdev))
                {
                    lm_igu_sb->status = LM_IGU_STATUS_AVAILABLE;
                }
                else
                {
                    lm_igu_sb->status = 0;
                }
                continue;
            }
            else
            {
                lm_igu_sb->status = LM_IGU_STATUS_VALID;
            }
            fid = (val & IGU_REG_MAPPING_MEMORY_FID_MASK) >> IGU_REG_MAPPING_MEMORY_FID_SHIFT;
            if (fid & IGU_FID_ENCODE_IS_PF)
            {
                current_pf_id = lm_igu_sb->pf_number = fid & IGU_FID_PF_NUM_MASK;
                if (lm_igu_sb->pf_number == FUNC_ID(pdev))
                {
                    lm_igu_sb->status |= (LM_IGU_STATUS_AVAILABLE | LM_IGU_STATUS_PF);
                }
                else
                {
                    lm_igu_sb->status |= LM_IGU_STATUS_PF;
                }
            }
            else
            {
                lm_igu_sb->vf_number = fid & IGU_FID_VF_NUM_MASK;
                if ((lm_igu_sb->vf_number >= pdev->hw_info.sriov_info.first_vf_in_pf)
                    && (lm_igu_sb->vf_number < (pdev->hw_info.sriov_info.first_vf_in_pf + pdev->hw_info.sriov_info.total_vfs)))
                {
                    lm_igu_sb->status |= LM_IGU_STATUS_AVAILABLE;
                }
            }
            lm_igu_sb->vector_number = (val & IGU_REG_MAPPING_MEMORY_VECTOR_MASK) >> IGU_REG_MAPPING_MEMORY_VECTOR_SHIFT;
            DbgMessage(pdev, VERBOSEi, "FID[%d]=%d\n", igu_sb_id, fid);
            if ((IS_PFDEV(pdev) && IGU_CAM_PFID_MATCH(pdev, fid)) ||
                (IS_VFDEV(pdev) && IGU_CAM_VFID_MATCH(pdev, fid)))
            {
                vec = (val & IGU_REG_MAPPING_MEMORY_VECTOR_MASK) >> IGU_REG_MAPPING_MEMORY_VECTOR_SHIFT;
                DbgMessage(pdev, INFORMi, "VEC[%d]=%d\n", igu_sb_id, vec);
                if (igu_test_vectors)
                {
                    blk_info->igu_info.igu_test_sb_cnt++;
                }
                else
                {
                    if (vec == 0 && IS_PFDEV(pdev))
                    {
                        /* default status block for default segment + attn segment */
                        blk_info->igu_info.igu_dsb_id = igu_sb_id;
                    }
                    else
                    {
                        if (blk_info->igu_info.igu_base_sb == 0xff)
                        {
                            blk_info->igu_info.igu_base_sb = igu_sb_id;
                        }
                        /* we don't count the default */
                        blk_info->igu_info.igu_sb_cnt++;
                    }
                }
                if (recent_vf_id != 0xFF)
                {
                    if (!blk_info->igu_info.vf_igu_info[recent_vf_id].igu_test_mode)
                    {
                        DbgMessage(pdev, WARN, "Consecutiveness of IGU for VF%d is broken. My be it's IGU test mode\n",recent_vf_id);
                    }
                    blk_info->igu_info.vf_igu_info[recent_vf_id].igu_test_mode = TRUE;
                }
            }
            else if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev))
            {
                if (!(fid & IGU_FID_ENCODE_IS_PF))
                {
                     vf_id = fid & IGU_FID_VF_NUM_MASK;
                     if (blk_info->igu_info.vf_igu_info[vf_id].igu_base_sb == 0xff)
                     {
                         blk_info->igu_info.vf_igu_info[vf_id].igu_base_sb = igu_sb_id;
                     }
                     /* we don't count the default */
                     if (recent_vf_id != vf_id)
                     {
                         if (recent_vf_id != 0xFF)
                         {
                             if (!blk_info->igu_info.vf_igu_info[recent_vf_id].igu_test_mode)
                             {
                                 DbgMessage(pdev, WARN, "Consecutiveness of IGU for VF%d is broken. My be it's IGU test mode\n",recent_vf_id);
                             }
                             blk_info->igu_info.vf_igu_info[recent_vf_id].igu_test_mode = TRUE;
                         }
                     }
                     recent_vf_id = vf_id;
                     if (blk_info->igu_info.vf_igu_info[vf_id].igu_test_mode)
                     {
                         blk_info->igu_info.vf_igu_info[vf_id].igu_test_sb_cnt++;
                     }
                     else
                     {
                         blk_info->igu_info.vf_igu_info[vf_id].igu_sb_cnt++;
                     }
                }
                else
                {
                    if (recent_vf_id != 0xFF)
                    {
                        if (!blk_info->igu_info.vf_igu_info[recent_vf_id].igu_test_mode)
                        {
                                DbgMessage(pdev, WARN, "Consecutiveness of IGU for VF%d is broken. My be it's IGU test mode\n",recent_vf_id);
                        }
                        blk_info->igu_info.vf_igu_info[recent_vf_id].igu_test_mode = TRUE;
                    }
                }
                if (blk_info->igu_info.igu_base_sb != 0xff)
                {
                    /* We've already found our base... but now we don't match... these are now igu-test-vectors */
                    if (!igu_test_vectors)
                    {
                            DbgMessage(pdev, WARN, "Consecutiveness of IGU is broken. My be it's IGU test mode\n");
                    }
                    igu_test_vectors = TRUE; //TODO Michals: take care of this!!!e2 igu_test will fail.
                }
            }
            else
            {
                /* No Match - belongs to someone else, check if breaks consecutiveness, if so, break at this point
                 * driver doesn't support non-consecutive vectors (EXCEPT Def sb...) */
                if (blk_info->igu_info.igu_base_sb != 0xff)
                {
                    /* We've already found our base... but now we don't match... these are now igu-test-vectors */
                    if (!igu_test_vectors) {
                        DbgMessage(pdev, WARN, "Consecutiveness of IGU is broken. My be it's IGU test mode\n");
                    }
                    igu_test_vectors = TRUE; //TODO Michals: take care of this!!!e2 igu_test will fail.
                }
            }
        }
        // TODO check cam is valid...
#ifndef _VBD_
        blk_info->igu_info.igu_sb_cnt = min(blk_info->igu_info.igu_sb_cnt, (u8_t)16);
#endif
        /* E2 TODO: if we don't want to separate u/c/ producers in IGU, this line needs to
         * be removed, and igu_u_offset needs to be set to 'zero'
        blk_info->igu_info.igu_u_sb_offset = blk_info->igu_info.igu_sb_cnt / 2;*/
        DbgMessage(pdev, WARN, "igu_sb_cnt=%d igu_dsb_id=%d igu_base_sb = %d igu_us_sb_offset = %d igu_test_cnt=%d\n",
                    blk_info->igu_info.igu_sb_cnt, blk_info->igu_info.igu_dsb_id, blk_info->igu_info.igu_base_sb, blk_info->igu_info.igu_u_sb_offset,
                    blk_info->igu_info.igu_test_sb_cnt);

        /* CQ61438 - do not show this error message in case of mf mode changed to SF and func >= 2*/
        if ((FUNC_ID(pdev) < 2) && (pdev->hw_info.mf_info.mf_mode != SINGLE_FUNCTION))
        {
            if (blk_info->igu_info.igu_sb_cnt < 1)
            {
                DbgMessage(pdev, FATAL, "Igu sb cnt is not valid value=%d\n", blk_info->igu_info.igu_sb_cnt);
            }
            if (blk_info->igu_info.igu_base_sb == 0xff)
            {
                DbgMessage(pdev, FATAL, "Igu base sb is not valid value=%d\n", blk_info->igu_info.igu_base_sb);
            }
        }

#define IGU_MAX_INTA_SB_CNT 31

        /* CQ72933/CQ72546
           In case we are in INTA mode, we limit the igu count to 31 as we can't handle more than that */
        if (pdev->params.b_inta_mode_prvided_by_os && (blk_info->igu_info.igu_sb_cnt > IGU_MAX_INTA_SB_CNT ))
        {
            blk_info->igu_info.igu_sb_cnt = IGU_MAX_INTA_SB_CNT ;
        }
    }

    DbgMessage(pdev, WARN, "IGU CAM INFO: BASE_SB: %d DSB: %d IGU_SB_CNT: %d\n", blk_info->igu_info.igu_base_sb, blk_info->igu_info.igu_dsb_id, blk_info->igu_info.igu_sb_cnt);
}
/*
 * Assumptions:
 *  - the following are initialized before call to this function:
 *    chip-id, func-rel,
 */
lm_status_t lm_get_intr_blk_info(lm_device_t *pdev)
{
    lm_intr_blk_info_t *blk_info = &pdev->hw_info.intr_blk_info;
    u32_t bar_base;
    u8_t igu_func_id = 0;

    if (CHIP_IS_E1x(pdev))
    {
        blk_info->blk_type         = INTR_BLK_HC;
        blk_info->access_type      = INTR_BLK_ACCESS_GRC;
        blk_info->blk_mode         = INTR_BLK_MODE_NORM;
        blk_info->simd_addr_womask = HC_REG_COMMAND_REG + PORT_ID(pdev)*32 + COMMAND_REG_SIMD_NOMASK;
        /* The next part is tricky... and has to do with an emulation work-around for handling interrupts, in which
         * we want to read without mask - always... so we take care of it here, instead of changing different ums to
         * call approriate function */
        if (CHIP_REV_IS_EMUL(pdev))
        {
            blk_info->simd_addr_wmask = HC_REG_COMMAND_REG + PORT_ID(pdev)*32 + COMMAND_REG_SIMD_NOMASK;
        }
        else
        {
            blk_info->simd_addr_wmask = HC_REG_COMMAND_REG + PORT_ID(pdev)*32 + COMMAND_REG_SIMD_MASK;
        }
    }
    else
    {
        /* If we have more than 32 status blocks we'll need to read from IGU_REG_SISR_MDPC_WMASK_UPPER */
        ASSERT_STATIC(MAX_RSS_CHAINS <= 32);
        pdev->hw_info.intr_blk_info.blk_type = INTR_BLK_IGU;
        if (REG_RD(PFDEV(pdev), IGU_REG_BLOCK_CONFIGURATION) & IGU_BLOCK_CONFIGURATION_REG_BACKWARD_COMP_EN)
        {
            DbgMessage(pdev, FATAL, "IGU Backward Compatible Mode\n");
            blk_info->blk_mode = INTR_BLK_MODE_BC;
        }
        else
        {
            DbgMessage(pdev, WARN, "IGU Normal Mode\n");
            blk_info->blk_mode = INTR_BLK_MODE_NORM;
        }
        /* read CAM to get igu info (must be called after we know if we're in backward compatible mode or not )*/
        lm_get_igu_cam_info(pdev);

        igu_func_id = (1 << IGU_FID_ENCODE_IS_PF_SHIFT) | FUNC_ID(pdev);
        blk_info->igu_info.igu_func_id = igu_func_id;
        if (pdev->params.igu_access_mode == INTR_BLK_ACCESS_GRC)
        {
            DbgMessage(pdev, FATAL, "IGU -  GRC\n");
            if (IS_VFDEV(pdev))
            {
                DbgBreakMsg("VF Can't work in GRC Access mode!\n");
                return LM_STATUS_FAILURE;
            }
            blk_info->access_type = INTR_BLK_ACCESS_GRC;
            /* [18:12] - FID (if VF - [18] = 0; [17:12] = VF number; if PF - [18] = 1; [17:14] = 0; [13:12] = PF number) */
            blk_info->cmd_ctrl_rd_womask =
            ((IGU_REG_SISR_MDPC_WOMASK_UPPER << IGU_CTRL_REG_ADDRESS_SHIFT) |
             (igu_func_id << IGU_CTRL_REG_FID_SHIFT) |
             (IGU_CTRL_CMD_TYPE_RD << IGU_CTRL_REG_TYPE_SHIFT));
            blk_info->simd_addr_womask = IGU_REG_COMMAND_REG_32LSB_DATA; /* this is where data will be after writing ctrol reg... */
            /* The next part is tricky... and has to do with an emulation work-around for handling interrupts, in which
             * we want to read without mask - always... so we take care of it here, instead of changing different ums to
             * call approriate function */
            if (CHIP_REV_IS_EMUL(pdev))
            {
                blk_info->cmd_ctrl_rd_wmask =
                ((IGU_REG_SISR_MDPC_WOMASK_UPPER << IGU_CTRL_REG_ADDRESS_SHIFT) |
                 (igu_func_id << IGU_CTRL_REG_FID_SHIFT) |
                 (IGU_CTRL_CMD_TYPE_RD << IGU_CTRL_REG_TYPE_SHIFT));
            }
            else
            {
                blk_info->cmd_ctrl_rd_wmask =
                ((IGU_REG_SISR_MDPC_WMASK_LSB_UPPER << IGU_CTRL_REG_ADDRESS_SHIFT) |
                 (igu_func_id << IGU_CTRL_REG_FID_SHIFT) |
                 (IGU_CTRL_CMD_TYPE_RD << IGU_CTRL_REG_TYPE_SHIFT));
            }
            blk_info->simd_addr_wmask = IGU_REG_COMMAND_REG_32LSB_DATA; /* this is where data will be after writing ctrol reg... */
        }
        else
        {
            DbgMessage(pdev, WARN, "IGU  - IGUMEM\n");
            blk_info->access_type = INTR_BLK_ACCESS_IGUMEM;
            bar_base = IS_PFDEV(pdev)? BAR_IGU_INTMEM : VF_BAR0_IGU_OFFSET;
            blk_info->simd_addr_womask = bar_base + IGU_REG_SISR_MDPC_WOMASK_UPPER*8;
            /* The next part is tricky... and has to do with an emulation work-around for handling interrupts, in which
             * we want to read without mask - always... so we take care of it here, instead of changing different ums to
             * call approriate function */
            if (CHIP_REV_IS_EMUL(pdev))
            {
                blk_info->simd_addr_wmask = bar_base + IGU_REG_SISR_MDPC_WOMASK_UPPER*8;
            }
            else
            {
                blk_info->simd_addr_wmask = bar_base + IGU_REG_SISR_MDPC_WMASK_LSB_UPPER*8;
            }
        }
    }
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_get_nvm_info(lm_device_t *pdev)
{
    u32_t val = REG_RD(pdev,MCP_REG_MCPR_NVM_CFG4);

    pdev->hw_info.flash_spec.total_size = NVRAM_1MB_SIZE << (val & MCPR_NVM_CFG4_FLASH_SIZE);
    pdev->hw_info.flash_spec.page_size  = NVRAM_PAGE_SIZE;

    return LM_STATUS_SUCCESS;
}
#if defined(DOS) || defined(__LINUX)
/* for ediag + lediat we don't really care about licensing!... */
#define DEFAULT_CONNECTIONS_TOE 1880
#define MAX_CONNECTIONS         2048  /* Max 32K Connections per port / vnic-per-port (rounded  to power2)*/
#define MAX_CONNECTIONS_ISCSI    128
#define MAX_CONNECTIONS_RDMA      10
#define MAX_CONNECTIONS_TOE     1880
#define MAX_CONNECTIONS_FCOE       0
#define MAX_CONNECTIONS_VF       128

#else

#define MAX_CONNECTIONS (min(16384,(32768 / (log2_align(pdev->hw_info.mf_info.vnics_per_port)))))  /* Max 32K Connections per port / vnic-per-port (rounded  to power2)
                                                                                                   but no more 16K to limit ilt client page size by 64KB*/

#define DEFAULT_CONNECTIONS_TOE 1880
#define MAX_CONNECTIONS_ISCSI    128
#define MAX_CONNECTIONS_RDMA      10
#define MAX_CONNECTIONS_FCOE    1024
#define MAX_CONNECTIONS_VF      (1 << (LM_VF_MAX_RVFID_SIZE + LM_MAX_VF_CID_WND_SIZE + 1))
#define MAX_CONNECTIONS_TOE     (min(8192,MAX_CONNECTIONS - MAX_CONNECTIONS_ISCSI - MAX_CONNECTIONS_RDMA - MAX_CONNECTIONS_FCOE - MAX_ETH_CONS - MAX_CONNECTIONS_VF))

#endif


#define MAX_CONNECTIONS_TOE_NO_LICENSE   0
#define MAX_CONNECTIONS_ISCSI_NO_LICENSE 0
#define MAX_CONNECTIONS_RDMA_NO_LICENSE  0
#define MAX_CONNECTIONS_FCOE_NO_LICENSE  0

#define MAX_CONNECTIONS_FCOE_NO_MCP      128

static u32_t lm_parse_license_info(u32 val, u8_t is_high)
{
    if (is_high)
    {
        val &=0xFFFF0000;
        if(val)
        {
            val ^= FW_ENCODE_32BIT_PATTERN;
        }
        val >>= 16;
    }
    else
    {
        val &= 0xffff;
        if(val)
        {
            val ^= FW_ENCODE_16BIT_PATTERN;
        }
    }
    return val;
}

static u32_t lm_parse_license_info_bounded(u32 val, u32_t max_cons, u8_t is_high)
{
    u32_t license_from_shmem =0;
    license_from_shmem = lm_parse_license_info(val, is_high);

    val = min(license_from_shmem, max_cons);
    return val;
}
/* No special MCP handling for a specific E1H configuration */
/* WARNING: Do Not Change these defines!!! They are used in an external tcl script that assumes their values!!! */
#define NO_MCP_WA_CFG_SET_ADDR            (0xA0000)
#define NO_MCP_WA_CFG_SET_MAGIC           (0x88AA55FF)
#define NO_MCP_WA_MULTI_VNIC_MODE         (0xA0004)
#define NO_MCP_WA_VNICS_PER_PORT(port)    (0xA0008 + 4*(port))
#define NO_MCP_WA_OVLAN(func)             (0xA0010 + 4*(func)) // --> 0xA0030
#define NO_MCP_WA_FORCE_5710              (0xA0030)
#define NO_MCP_WA_VALID_LIC_ADDR          (0xA0040)
#define NO_MCP_WA_VALID_LIC_MAGIC         (0xCCAAFFEE)
#define NO_MCP_WA_TOE_LIC                 (0xA0048)
#define NO_MCP_WA_ISCSI_LIC               (0xA0050)
#define NO_MCP_WA_RDMA_LIC                (0xA0058)
#define NO_MCP_WA_CLC_SHMEM               (0xAF900)

static lm_status_t lm_get_shmem_license_info(lm_device_t *pdev)
{
    u32_t max_toe_cons[PORT_MAX]           = {0,0};
    u32_t max_rdma_cons[PORT_MAX]          = {0,0};
    u32_t max_iscsi_cons[PORT_MAX]         = {0,0};
    u32_t max_fcoe_cons[PORT_MAX]          = {0,0};
    u32_t max_eth_cons[PORT_MAX]           = {0,0}; /* Includes VF connections */
    u32_t max_bar_supported_cons[PORT_MAX] = {0};
    u32_t max_supported_cons[PORT_MAX]     = {0};
    u32_t val                              = 0;
    u8_t  port                             = 0;
    u32_t offset                           = 0;

    /* Even though only one port actually does the initialization, ALL functions need to know the maximum number of connections
     * because that's how they know what the page-size-is, and based on that do per-function initializations as well. */
    pdev->hw_info.max_common_conns = 0;

    /* get values for relevant ports. */
    for (port = 0; port < PORT_MAX; port++)
    {
        if (pdev->hw_info.mcp_detected == 1)
        {
            LM_SHMEM_READ(pdev, OFFSETOF(shmem_region_t, validity_map[port]),&val);

            // check that licensing is enabled
            if(GET_FLAGS(val, SHR_MEM_VALIDITY_LIC_MANUF_KEY_IN_EFFECT | SHR_MEM_VALIDITY_LIC_UPGRADE_KEY_IN_EFFECT))
            {
                // align to 32 bit
                offset = OFFSETOF(shmem_region_t, drv_lic_key[port].max_toe_conn) & 0xfffffffc;
                LM_SHMEM_READ(pdev, offset, &val);
                max_toe_cons[port] = lm_parse_license_info_bounded(val, MAX_CONNECTIONS_TOE,FALSE);
                DbgMessage(pdev, INFORMi, "max_toe_conn from shmem %d for port %d\n",val, port);
                /* RDMA */
                offset = OFFSETOF(shmem_region_t, drv_lic_key[port].max_um_rdma_conn) & 0xfffffffc;
                LM_SHMEM_READ(pdev, offset, &val);
                max_rdma_cons[port] = lm_parse_license_info_bounded(val, MAX_CONNECTIONS_RDMA,FALSE);
                DbgMessage(pdev, INFORMi, "max_rdma_conn from shmem %d for port %d\n",val, port);
                /* ISCSI */
                offset = OFFSETOF(shmem_region_t, drv_lic_key[port].max_iscsi_trgt_conn) & 0xfffffffc;
                LM_SHMEM_READ(pdev, offset, &val);
                max_iscsi_cons[port] = lm_parse_license_info_bounded(val, MAX_CONNECTIONS_ISCSI,TRUE);
                DbgMessage(pdev, INFORMi, "max_iscsi_conn from shmem %d for port %d\n",val, port);
                /* FCOE */
                offset = OFFSETOF(shmem_region_t, drv_lic_key[port].max_fcoe_init_conn) & 0xfffffffc;
                LM_SHMEM_READ(pdev, offset, &val);
                if(0 == lm_parse_license_info(val,TRUE))
                {
                    max_fcoe_cons[port] = 0;
                }
                else
                {
                    max_fcoe_cons[port] = MAX_CONNECTIONS_FCOE;
                }
                DbgMessage(pdev, INFORMi, "max_fcoe_conn from shmem %d for port %d\n",val, port);

            }
            else
            {
                // In case MCP is enabled and there is no licence => there should be no offload connection.
                max_toe_cons[port]      = MAX_CONNECTIONS_TOE_NO_LICENSE;
                max_rdma_cons[port]     = MAX_CONNECTIONS_ISCSI_NO_LICENSE;
                max_iscsi_cons[port]    = MAX_CONNECTIONS_RDMA_NO_LICENSE;
                max_fcoe_cons[port]     = MAX_CONNECTIONS_FCOE_NO_LICENSE;
            }
            if (CHIP_IS_E1x(pdev))
            {
                max_eth_cons[port] = MAX_ETH_REG_CONS;
            }
            else
            {
                max_eth_cons[port] = MAX_CONNECTIONS_VF;
            }

            /* get the bar size... unless it's current port and then we have it. otherwise, read from shmem W.C which
             * is what the other ports asked for, they could have gotten less, but we're looking into the worst case. */
            if (PORT_ID(pdev) == port)
            {
                max_bar_supported_cons[port] = pdev->hw_info.bar_size[BAR_1] / LM_DQ_CID_SIZE;
            }
            else
            {
                LM_SHMEM_READ(pdev, OFFSETOF(shmem_region_t, dev_info.port_feature_config[port].config), &val);
                val = (val & PORT_FEAT_CFG_BAR2_SIZE_MASK) >> PORT_FEAT_CFG_BAR2_SIZE_SHIFT;
                if (val != 0)
                 {
                    /* bit 1 stand for 64K each bit multiply it by two */
                    val = (0x40 << ((val - 1)))*0x400;
                }
                max_bar_supported_cons[port] = val / LM_DQ_CID_SIZE;
            }
        }
        else
        {
            // MCP_WA
            LM_SHMEM_READ(pdev, NO_MCP_WA_VALID_LIC_ADDR+4*port, &val);

            if (val == NO_MCP_WA_VALID_LIC_MAGIC)
            {
                LM_SHMEM_READ(pdev, NO_MCP_WA_TOE_LIC+4*port, &val);
                max_toe_cons[port] = val;
                LM_SHMEM_READ(pdev, NO_MCP_WA_ISCSI_LIC+4*port, &val);
                max_iscsi_cons[port] = val;
                LM_SHMEM_READ(pdev, NO_MCP_WA_RDMA_LIC+4*port, &val);
                max_rdma_cons[port] = val;

                /* FCOE */
                // For backward compatibility, same value if it will be required we can add NO_MCP_WA_FCOE_LIC
                max_fcoe_cons[port] = MAX_CONNECTIONS_FCOE_NO_MCP;
                // Fcoe licencing isn't supported.
                /*
                LM_SHMEM_READ(pdev, NO_MCP_WA_FCOE_LIC+4*port, &val);
                max_fcoe_cons[port] = val;
                */
            }
            else
            {
                #ifdef VF_INVOLVED
                max_toe_cons[port] = DEFAULT_CONNECTIONS_TOE - 100;
                #else
                max_toe_cons[port] = DEFAULT_CONNECTIONS_TOE;
                #endif
                max_iscsi_cons[port] = MAX_CONNECTIONS_ISCSI;
                max_rdma_cons[port]  = MAX_CONNECTIONS_RDMA;
                // Need to review this value seems like we take in this case the max value
                max_fcoe_cons[port] = MAX_CONNECTIONS_FCOE_NO_MCP;
            }
            if (CHIP_IS_E1x(pdev))
            {
                max_eth_cons[port] = MAX_ETH_REG_CONS;
            }
            else
            {
                max_eth_cons[port] = MAX_CONNECTIONS_VF;
            }
            /* For MCP - WA, we always assume the same bar size for all ports: makes life simpler... */
            max_bar_supported_cons[port] = pdev->hw_info.bar_size[BAR_1] / LM_DQ_CID_SIZE;
        }
        /* so after all this - what is the maximum number of connections supported for this port? */
        max_supported_cons[port] = log2_align(max_toe_cons[port] + max_rdma_cons[port] + max_iscsi_cons[port] + max_fcoe_cons[port] + max_eth_cons[port]);
        max_supported_cons[port] = min(max_supported_cons[port], max_bar_supported_cons[port]);

        /* And after all this... in lediag  / ediag... we assume a maximum of 1024 connections */
        #if defined(DOS) || defined(__LINUX)
        max_supported_cons[port] = min(max_supported_cons[port], (u32_t)1024);
        #endif

        if (max_supported_cons[port] > pdev->hw_info.max_common_conns)
        {
            pdev->hw_info.max_common_conns = max_supported_cons[port];
        }


    }
    /* Now, port specific... */
    port = PORT_ID(pdev);
    /* now, there could be a problem where the bar limited us, and the max-connections is smaller than the total above, in this case we need to decrease the
     * numbers relatively... can't touch MAX_ETH_CONS... */
    if (ERR_IF(max_supported_cons[port] < max_eth_cons[port]))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }
    if ((max_iscsi_cons[port]  + max_rdma_cons[port] +  max_toe_cons[port] + max_fcoe_cons[port] + max_eth_cons[port]) > max_supported_cons[port])
    {
        /* we first try giving iscsi + rdma what they asked for... */
        if ((max_iscsi_cons[port] + max_rdma_cons[port] + max_fcoe_cons[port] + max_eth_cons[port]) > max_supported_cons[port])
        {
            u32_t s = max_iscsi_cons[port] + max_rdma_cons[port] +  max_toe_cons[port] + max_fcoe_cons[port]; /* eth out of the game... */
            u32_t t = max_supported_cons[port] - pdev->params.max_eth_including_vfs_conns; /* what we want to reach... */
            /* relatively decrease all... (x+y+z=s, actual = t: xt/s+yt/s+zt/s = t) */
            max_iscsi_cons[port] *=t;
            max_iscsi_cons[port] /=s;
            max_rdma_cons[port]  *=t;
            max_rdma_cons[port]  /=s;
            max_toe_cons[port]   *=t;
            max_toe_cons[port]   /=s;
            max_fcoe_cons[port]  *=t;
            max_fcoe_cons[port]  /=s;
        }
        else
         {
            /* just give toe what's left... */
            max_toe_cons[port] = max_supported_cons[port] - (max_iscsi_cons[port] + max_rdma_cons[port]  + max_fcoe_cons[port] + max_eth_cons[port]);
        }
    }
    if (ERR_IF((max_iscsi_cons[port]  + max_rdma_cons[port] + max_fcoe_cons[port] + max_toe_cons[port] + max_eth_cons[port]) > max_supported_cons[port]))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* Now lets save our port-specific variables. By this stage we have the maximum supported connections for our port. */
    pdev->hw_info.max_port_toe_conn = max_toe_cons[port];
    DbgMessage(pdev, INFORMi, "max_toe_conn from shmem %d\n",pdev->hw_info.max_port_toe_conn);
    /* RDMA */
    pdev->hw_info.max_port_rdma_conn = max_rdma_cons[port];
    DbgMessage(pdev, INFORMi, "max_rdma_conn from shmem %d\n",pdev->hw_info.max_port_rdma_conn);
    /* ISCSI */
    pdev->hw_info.max_port_iscsi_conn = max_iscsi_cons[port];
    DbgMessage(pdev, INFORMi, "max_iscsi_conn from shmem %d\n",pdev->hw_info.max_port_iscsi_conn);
    /* FCOE */
    pdev->hw_info.max_port_fcoe_conn = max_fcoe_cons[port];
    DbgMessage(pdev, INFORMi, "max_fcoe_conn from shmem %d\n",pdev->hw_info.max_port_fcoe_conn);

    pdev->hw_info.max_port_conns = log2_align(pdev->hw_info.max_port_toe_conn +
                                              pdev->hw_info.max_port_rdma_conn + pdev->hw_info.max_port_iscsi_conn
                                              + pdev->hw_info.max_port_fcoe_conn + pdev->params.max_eth_including_vfs_conns);

    if (ERR_IF(pdev->hw_info.max_port_conns > max_bar_supported_cons[port]))
    {
        /* this would mean an error in the calculations above. */
        return LM_STATUS_INVALID_PARAMETER;
    }

    return LM_STATUS_SUCCESS;
}
static lm_status_t lm_check_valid_mf_cfg(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info    = &pdev->hw_info.mf_info;
    lm_status_t           lm_status   = LM_STATUS_SUCCESS;
    const u8_t            func_id     = FUNC_ID(pdev);
    u8_t                  i           = 0;
    u8_t                  j           = 0;
    u32_t                 mf_cfg1     = 0;
    u32_t                 mf_cfg2     = 0;
    u32_t                 ovlan1      = 0;
    u32_t                 ovlan2      = 0;
    u32_t                 dynamic_cfg = 0;

    /* hard coded offsets in vnic_cfg.tcl. if assertion here fails,
     * need to fix vnic_cfg.tcl script as well. */
//    ASSERT_STATIC(OFFSETOF(shmem_region_t,mf_cfg)            == 0x7e4);
    ASSERT_STATIC(OFFSETOF(mf_cfg_t,shared_mf_config.clp_mb) == 0);
  //ASSERT_STATIC(MCP_CLP_MB_NO_CLP                          == 0x80000000); not yet defined
    ASSERT_STATIC(OFFSETOF(mf_cfg_t,func_mf_config)          == 36);
    ASSERT_STATIC(OFFSETOF(func_mf_cfg_t,config)             == 0);
    ASSERT_STATIC(FUNC_MF_CFG_FUNC_HIDE                      == 0x1);
    ASSERT_STATIC(FUNC_MF_CFG_PROTOCOL_ETHERNET_WITH_RDMA    == 0x4);
    ASSERT_STATIC(FUNC_MF_CFG_FUNC_DISABLED                  == 0x8);
    ASSERT_STATIC(OFFSETOF(func_mf_cfg_t,mac_upper)          == 4);
    ASSERT_STATIC(OFFSETOF(func_mf_cfg_t,mac_lower)          == 8);
    ASSERT_STATIC(FUNC_MF_CFG_UPPERMAC_DEFAULT               == 0x0000ffff);
    ASSERT_STATIC(FUNC_MF_CFG_LOWERMAC_DEFAULT               == 0xffffffff);
    ASSERT_STATIC(OFFSETOF(func_mf_cfg_t,e1hov_tag)          == 12);
    ASSERT_STATIC(FUNC_MF_CFG_E1HOV_TAG_DEFAULT              == 0x0000ffff);
    ASSERT_STATIC(sizeof(func_mf_cfg_t)                      == 24);

    /* trace mf cfg parameters */
    DbgMessage(pdev, INFORMi, "MF cfg parameters for function %d:\n", func_id);
    DbgMessage(pdev, INFORMi, "\t func_mf_cfg=0x%x\n\t multi_vnics_mode=%d\n\t vnics_per_port=%d\n\t ovlan/vifid=%d\n\t min_bw=%d\n\t max_bw=%d\n",
                mf_info->func_mf_cfg,
                mf_info->vnics_per_port,
                mf_info->multi_vnics_mode,
                mf_info->ext_id,
                mf_info->min_bw,
                mf_info->max_bw);
    DbgMessage(pdev, INFORMi, "\t mac addr (overiding main and iscsi): %02x %02x %02x %02x %02x %02x\n",
            pdev->hw_info.mac_addr[0],
            pdev->hw_info.mac_addr[1],
            pdev->hw_info.mac_addr[2],
            pdev->hw_info.mac_addr[3],
            pdev->hw_info.mac_addr[4],
            pdev->hw_info.mac_addr[5]);

    /* verify that function is not hidden */
    if (GET_FLAGS(mf_info->func_mf_cfg, FUNC_MF_CFG_FUNC_HIDE))
    {
        DbgMessage(pdev, FATAL, "Enumerated function %d, is marked as hidden\n", func_id);
        lm_status = LM_STATUS_FAILURE;
        goto _end;
    }

    if (mf_info->vnics_per_port > 1 && !mf_info->multi_vnics_mode)
    {
        DbgMessage(pdev, FATAL, "invalid mf mode configuration: vnics_per_port=%d, multi_vnics_mode=%d\n",
                    mf_info->vnics_per_port,
                    mf_info->multi_vnics_mode);
        lm_status = LM_STATUS_FAILURE;
        //DbgBreakIf(1);
        goto _end;
    }

    /* Sanity checks on outer-vlan for switch_dependent_mode... */
    if (mf_info->mf_mode == MULTI_FUNCTION_SD)
    {
        /* enumerated vnic id > 0 must have valid ovlan if we're in switch-dependet mode */
        if ((VNIC_ID(pdev) > 0) && !VALID_OVLAN(OVLAN(pdev)))
        {
            DbgMessage(pdev, WARNi, "invalid mf mode configuration: VNICID=%d, Function is enumerated, ovlan (%d) is invalid\n",
                        VNIC_ID(pdev), OVLAN(pdev));
#ifdef EDIAG
            // Allow OVLAN 0xFFFF in ediag UFP mode
            if (mf_info->sd_mode != SD_UFP_MODE) 
            {
                lm_status = LM_STATUS_FAILURE;
            }
#else
            lm_status = LM_STATUS_FAILURE;
#endif
            goto _end;
        }

        /* additional sanity checks */
        if (!VALID_OVLAN(OVLAN(pdev)) && mf_info->multi_vnics_mode)
        {
            DbgMessage(pdev, FATAL, "invalid mf mode configuration: multi_vnics_mode=%d, ovlan=%d\n",
                        mf_info->multi_vnics_mode,
                        OVLAN(pdev));
#ifdef EDIAG
            // Allow OVLAN 0xFFFF in ediag UFP mode
            if (mf_info->sd_mode != SD_UFP_MODE) 
            {
                lm_status = LM_STATUS_FAILURE;
            }
#else
            lm_status = LM_STATUS_FAILURE;
#endif
            goto _end;
        }
        /* verify all functions are either mf mode or sf mode:
         * if we set mode to mf, make sure that all non hidden functions have valid ovlan
         * if we set mode to sf, make sure that all non hidden functions have invalid ovlan */
        LM_FOREACH_ABS_FUNC_IN_PORT(pdev, i)
        {
            LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[i].config),&mf_cfg1);
            LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[i].e1hov_tag), &ovlan1);
            if (!GET_FLAGS(mf_cfg1, FUNC_MF_CFG_FUNC_HIDE) &&
                (((mf_info->multi_vnics_mode) && !VALID_OVLAN(ovlan1)) ||
                 ((!mf_info->multi_vnics_mode) && VALID_OVLAN(ovlan1))))
            {
#ifdef EDIAG
				// Allow OVLAN 0xFFFF in eDiag UFP mode
                if (mf_info->sd_mode != SD_UFP_MODE) 
                {       
	                lm_status = LM_STATUS_FAILURE;                
                }
#else
		lm_status= LM_STATUS_FAILURE;
#endif
                goto _end;
            }
        }
        /* verify different ovlan between funcs on same port */
        LM_FOREACH_ABS_FUNC_IN_PORT(pdev, i)
        {
            LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[i].config),&mf_cfg1);
            LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[i].e1hov_tag), &ovlan1);
            /* iterate from the next function in the port till max func */
            for (j = i + 2; j < E1H_FUNC_MAX; j += 2)
            {
                LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[j].config),&mf_cfg2);
                LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[j].e1hov_tag), &ovlan2);
                if (!GET_FLAGS(mf_cfg1, FUNC_MF_CFG_FUNC_HIDE) && VALID_OVLAN(ovlan1) &&
                    !GET_FLAGS(mf_cfg2, FUNC_MF_CFG_FUNC_HIDE) && VALID_OVLAN(ovlan2) &&
                    (ovlan1 == ovlan2) )
                {
                    lm_status = LM_STATUS_FAILURE;
                    DbgBreakIf(1);
                    goto _end;
                }
            }
        }
        // Check if DCC is active (Debugging only)
        LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, port_mf_config[PATH_ID(pdev)][PORT_ID(pdev)].dynamic_cfg),&dynamic_cfg );
        if( PORT_MF_CFG_E1HOV_TAG_DEFAULT == ( dynamic_cfg & PORT_MF_CFG_E1HOV_TAG_MASK ) )
        {
            pdev->hw_info.is_dcc_active = FALSE;
        }
        else
        {
            pdev->hw_info.is_dcc_active = TRUE;
        }
    } // MULTI_FUNCTION_SD
_end:
    return lm_status;
}

void lm_cmng_get_shmem_info( lm_device_t* pdev )
{
    u32_t                  val     = 0;
    u8_t                   i       = 0;
    u8_t                   vnic    = 0;
    lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;;

    if( !IS_MF_MODE_CAPABLE(pdev) )
    {
        DbgBreakIf(1) ;
        return;
    }

    LM_FOREACH_ABS_FUNC_IN_PORT(pdev, i)
    {
        LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[i].config),&val);
        /* get min/max bw */
        mf_info->min_bw[vnic] = (GET_FLAGS(val, FUNC_MF_CFG_MIN_BW_MASK) >> FUNC_MF_CFG_MIN_BW_SHIFT);
        mf_info->max_bw[vnic] = (GET_FLAGS(val, FUNC_MF_CFG_MAX_BW_MASK) >> FUNC_MF_CFG_MAX_BW_SHIFT);
        vnic++;
    }
}

/**lm_get_vnics_per_port
 * Get the value of vnics_per_port according to the MF mode and
 * port mode.
 *
 * Note: This function assumes that multi_vnics_mode and
 * chip_port_mode are initialized in hw_info.
 *
 * @param pdev
 *
 * @return u8_t the value of vnics_per_port for this pdev's port
 *         mode and MF mode. This value does not consider hidden
 *         PFs.
 */
static u8_t lm_get_vnics_per_port(lm_device_t* pdev)
{
    if (pdev->hw_info.mf_info.multi_vnics_mode)
    {
        return LM_PFS_PER_PORT(pdev);
    }
    else
    {
        return 1;
    }
}

/* Get shmem multi function config info for switch dependent mode */
static lm_status_t lm_get_shmem_mf_cfg_info_sd(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;
    u32_t                  val     = 0;

    /* get ovlan if we're in switch-dependent mode... */
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].e1hov_tag),&val);
    mf_info->ext_id = (u16_t)val;

    mf_info->multi_vnics_mode = 1;
    if(!VALID_OVLAN(OVLAN(pdev))) 
    {
        /* Unexpected at this time */
        DbgMessage(pdev, FATAL, "Invalid mf mode configuration: VNICID=%d, Function is enumerated, ovlan (%d) is invalid\n",
                   VNIC_ID(pdev), OVLAN(pdev));
#ifdef EDIAG
     	// Allow OVLAN 0xFFFF in ediag UFP mode
     	if (mf_info->sd_mode != SD_UFP_MODE) 
     	{
          	return LM_STATUS_FAILURE;
     	}
#else
        return LM_STATUS_FAILURE;
#endif
    }

    /* Get capabilities */
    if (GET_FLAGS(mf_info->func_mf_cfg, FUNC_MF_CFG_PROTOCOL_MASK) == FUNC_MF_CFG_PROTOCOL_ISCSI)
    {
        pdev->params.mf_proto_support_flags |= LM_PROTO_SUPPORT_ISCSI;
    }
    else if (GET_FLAGS(mf_info->func_mf_cfg, FUNC_MF_CFG_PROTOCOL_MASK) == FUNC_MF_CFG_PROTOCOL_FCOE)
    {
        pdev->params.mf_proto_support_flags |= LM_PROTO_SUPPORT_FCOE;
    }
    else
    {
        pdev->params.mf_proto_support_flags |= LM_PROTO_SUPPORT_ETHERNET;
    }

    mf_info->vnics_per_port = lm_get_vnics_per_port(pdev);

    return LM_STATUS_SUCCESS;
}


/* Get shmem multi function config info for switch dependent mode */
static lm_status_t lm_get_shmem_mf_cfg_info_sd_bd(lm_device_t *pdev)
{
    lm_status_t lm_status = lm_get_shmem_mf_cfg_info_sd(pdev);

    return lm_status;
}


/* Get shmem multi function config info for switch dependent mode */
static lm_status_t lm_get_shmem_mf_cfg_info_sd_ufp(lm_device_t *pdev)
{
    lm_status_t lm_status = lm_get_shmem_mf_cfg_info_sd(pdev);

    return lm_status;
}

static void _copy_mac_upper_lower_to_arr(IN u32_t mac_upper, IN u32_t mac_lower, OUT u8_t* mac_addr)
{
    if(mac_addr)
    {
        mac_addr[0] = (u8_t) (mac_upper >> 8);
        mac_addr[1] = (u8_t) mac_upper;
        mac_addr[2] = (u8_t) (mac_lower >> 24);
        mac_addr[3] = (u8_t) (mac_lower >> 16);
        mac_addr[4] = (u8_t) (mac_lower >> 8);
        mac_addr[5] = (u8_t) mac_lower;
    }
}

static void lm_get_shmem_ext_mac_addresses(lm_device_t *pdev)
{
    u32_t      mac_upper   = 0;
    u32_t      mac_lower   = 0;
    u32_t      offset      = 0;
    const u8_t abs_func_id = ABS_FUNC_ID(pdev);

    /* We have a different mac address per iscsi / fcoe - we'll set it from extended multi function info, but only if it's valid, otherwise
     * we'll leave the same mac as for L2
     */
    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].iscsi_mac_addr_upper);
    LM_MFCFG_READ(pdev, offset, &mac_upper);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].iscsi_mac_addr_lower);
    LM_MFCFG_READ(pdev, offset, &mac_lower);

    _copy_mac_upper_lower_to_arr(mac_upper, mac_lower, pdev->hw_info.iscsi_mac_addr);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].fcoe_mac_addr_upper);
    LM_MFCFG_READ(pdev, offset, &mac_upper);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].fcoe_mac_addr_lower);
    LM_MFCFG_READ(pdev, offset, &mac_lower);

    _copy_mac_upper_lower_to_arr(mac_upper, mac_lower, pdev->hw_info.fcoe_mac_addr);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].fcoe_wwn_port_name_upper);
    LM_MFCFG_READ(pdev, offset, &mac_upper);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].fcoe_wwn_port_name_lower);
    LM_MFCFG_READ(pdev, offset, &mac_lower);

    _copy_mac_upper_lower_to_arr(mac_upper, mac_lower, &(pdev->hw_info.fcoe_wwn_port_name[2]));
    pdev->hw_info.fcoe_wwn_port_name[0] = (u8_t) (mac_upper >> 24);
    pdev->hw_info.fcoe_wwn_port_name[1] = (u8_t) (mac_upper >> 16);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].fcoe_wwn_node_name_upper);
    LM_MFCFG_READ(pdev, offset, &mac_upper);

    offset = OFFSETOF(mf_cfg_t, func_ext_config[abs_func_id].fcoe_wwn_node_name_lower);
    LM_MFCFG_READ(pdev, offset, &mac_lower);

    _copy_mac_upper_lower_to_arr(mac_upper, mac_lower, &(pdev->hw_info.fcoe_wwn_node_name[2]));
    pdev->hw_info.fcoe_wwn_node_name[0] = (u8_t) (mac_upper >> 24);
    pdev->hw_info.fcoe_wwn_node_name[1] = (u8_t) (mac_upper >> 16);
}

static u32_t
lm_get_shmem_ext_proto_support_flags(lm_device_t *pdev)
{
    u32_t   func_ext_cfg        = 0;
    u32_t   proto_support_flags = 0;

    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_ext_config[ABS_FUNC_ID(pdev)].func_cfg),&func_ext_cfg);

    if (GET_FLAGS(func_ext_cfg, MACP_FUNC_CFG_FLAGS_ENABLED ))
    {
        if (GET_FLAGS(func_ext_cfg, MACP_FUNC_CFG_FLAGS_ETHERNET))
        {
            proto_support_flags |= LM_PROTO_SUPPORT_ETHERNET;
        }
        if (GET_FLAGS(func_ext_cfg, MACP_FUNC_CFG_FLAGS_ISCSI_OFFLOAD))
        {
            proto_support_flags |= LM_PROTO_SUPPORT_ISCSI;
        }
        if (GET_FLAGS(func_ext_cfg, MACP_FUNC_CFG_FLAGS_FCOE_OFFLOAD))
        {
            proto_support_flags |= LM_PROTO_SUPPORT_FCOE;
        }
    }

    return proto_support_flags;
}

/* Get shmem multi function config info for switch independent mode */
static lm_status_t lm_get_shmem_mf_cfg_info_si(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;
    u32_t val       = 0;

    /* No outer-vlan... we're in switch-independent mode, so if the mac is valid - assume multi-function */
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_ext_config[ABS_FUNC_ID(pdev)].func_cfg),&val);
    val = val & MACP_FUNC_CFG_FLAGS_MASK;
    mf_info->multi_vnics_mode = (val != 0);
    mf_info->path_has_ovlan = FALSE;

    pdev->params.mf_proto_support_flags = lm_get_shmem_ext_proto_support_flags(pdev);

    mf_info->vnics_per_port = lm_get_vnics_per_port(pdev);

    return LM_STATUS_SUCCESS;

}

lm_status_t lm_get_shmem_mf_cfg_info_niv(lm_device_t *pdev)
{
    lm_hardware_mf_info_t   *mf_info     = &pdev->hw_info.mf_info;
    u32_t                   func_config  = 0;
    u32_t                   niv_config   = 0;
    u32_t                   e1hov_tag    = 0;

    mf_info->multi_vnics_mode = TRUE;

    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].e1hov_tag),&e1hov_tag);
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].config), &func_config);
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].afex_config), &niv_config);

    mf_info->ext_id = (u16_t)(GET_FLAGS(e1hov_tag, FUNC_MF_CFG_E1HOV_TAG_MASK)>>FUNC_MF_CFG_E1HOV_TAG_SHIFT);
    mf_info->default_vlan = (u16_t)(GET_FLAGS(e1hov_tag, FUNC_MF_CFG_AFEX_VLAN_MASK)>>FUNC_MF_CFG_AFEX_VLAN_SHIFT);

    mf_info->niv_allowed_priorities = (u8_t)(GET_FLAGS(niv_config, FUNC_MF_CFG_AFEX_COS_FILTER_MASK)>>FUNC_MF_CFG_AFEX_COS_FILTER_SHIFT);
    mf_info->niv_default_cos = (u8_t)(GET_FLAGS(func_config, FUNC_MF_CFG_TRANSMIT_PRIORITY_MASK)>>FUNC_MF_CFG_TRANSMIT_PRIORITY_SHIFT);
    mf_info->afex_vlan_mode = GET_FLAGS(niv_config, FUNC_MF_CFG_AFEX_VLAN_MODE_MASK)>>FUNC_MF_CFG_AFEX_VLAN_MODE_SHIFT;
    mf_info->niv_mba_enabled = GET_FLAGS(niv_config, FUNC_MF_CFG_AFEX_MBA_ENABLED_MASK)>>FUNC_MF_CFG_AFEX_MBA_ENABLED_SHIFT;


    pdev->params.mf_proto_support_flags = lm_get_shmem_ext_proto_support_flags(pdev);

    mf_info->vnics_per_port = lm_get_vnics_per_port(pdev);

    return LM_STATUS_SUCCESS;
}

static lm_status_t lm_shmem_set_default(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info   = &pdev->hw_info.mf_info;
    u8_t i;

    /* set defaults: */
    mf_info->multi_vnics_mode = 0;
    mf_info->vnics_per_port   = 1;
    mf_info->ext_id           = 0xffff; /* invalid ovlan */ /* TBD - E1H: - what is the right value for Cisco? */

    ASSERT_STATIC( ARRSIZE(mf_info->min_bw) == ARRSIZE(mf_info->max_bw) )

    for (i = 0; i < ARRSIZE(mf_info->min_bw); i++)
    {
        mf_info->min_bw[i] = 0;
        mf_info->max_bw[i] = 200;
    }
    pdev->hw_info.shmem_base          = 0;
    pdev->hw_info.max_port_toe_conn   = MAX_CONNECTIONS_TOE;
    pdev->hw_info.max_port_rdma_conn  = MAX_CONNECTIONS_RDMA;
    pdev->hw_info.max_port_iscsi_conn = MAX_CONNECTIONS_ISCSI;
    pdev->hw_info.max_port_fcoe_conn  = MAX_CONNECTIONS_FCOE;
    pdev->hw_info.max_port_conns      = MAX_CONNECTIONS;
    pdev->hw_info.max_common_conns    = MAX_CONNECTIONS;

    return LM_STATUS_SUCCESS;
}

static u32_t lm_get_shmem_base_addr(lm_device_t *pdev)
{
    u32_t val            = 0;
    u32_t min_shmem_addr = 0;
    u32_t max_shmem_addr = 0;

    val = REG_RD(pdev,MISC_REG_SHARED_MEM_ADDR);
    if (CHIP_IS_E1(pdev))
    {
        min_shmem_addr = 0xa0000;
        max_shmem_addr = 0xb0000;
    }
    else if (CHIP_IS_E1H(pdev))
    {
       min_shmem_addr = 0xa0000;
       max_shmem_addr = 0xc0000;
    }
    else if (CHIP_IS_E2E3(pdev))
    {
        min_shmem_addr = 0x3a0000;
        max_shmem_addr = 0x3c8000;
    }
    else
    {
        u32 pcicfg_chip;
        mm_read_pci(pdev, 0, &pcicfg_chip);
        DbgMessage(pdev, FATAL , "Unknown chip 0x%x, pcicfg[0]=0x%x, GRC[0x2000]=0x%x\n",
                    CHIP_NUM(pdev), pcicfg_chip, REG_RD(pdev, 0x2000));
        DbgBreakMsg("Unknown chip version");
    }

    if (val < min_shmem_addr || val >= max_shmem_addr)
    {
        /* Invalid shmem base address return '0' */
        val = 0;
    }

    return val;
}

/**
 * @Description
 *     This function is called when MCP is not detected. It
 *     initializes lmdevice parameters that are required for
 *     functional running with default values or values read
 *     from vnic_cfg.tcl script.
 *
 * @param pdev
 *
 * @return lm_status_t
 */
static lm_status_t lm_get_shmem_info_no_mcp_bypass(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;
    lm_status_t lm_status          = LM_STATUS_SUCCESS;
    u32_t val                      = 0;


    DbgMessage(pdev, WARN, "MCP Down Detected\n");
#ifndef _VBD_CMD_
    val = REG_RD(pdev,MISC_REG_SHARED_MEM_ADDR);
    DbgMessage(pdev, FATAL, "FW ShMem addr: 0x%x\n", val);
#endif // _VBD_CMD_

    pdev->hw_info.mcp_detected = 0;
    /* should have a magic number written if configuration was set otherwise, use default above */
    LM_SHMEM_READ(pdev, NO_MCP_WA_CFG_SET_ADDR, &val);
    if (val == NO_MCP_WA_CFG_SET_MAGIC)
    {
        LM_SHMEM_READ(pdev, NO_MCP_WA_FORCE_5710, &val);
        LM_SHMEM_READ(pdev, NO_MCP_WA_MULTI_VNIC_MODE, &val);
        mf_info->multi_vnics_mode = (u8_t)val;
        if (mf_info->multi_vnics_mode)
        {
            LM_SHMEM_READ(pdev, NO_MCP_WA_OVLAN(ABS_FUNC_ID(pdev)), &val);
            mf_info->ext_id = (u16_t)val;

            mf_info->multi_vnics_mode = VALID_OVLAN(mf_info->ext_id)? 1 : 0;
            mf_info->path_has_ovlan = mf_info->multi_vnics_mode;

            /* decide on path multi vnics mode - incase we're not in mf mode...and in 4-port-mode good enough to check vnic-0 of the other port, on the same path */
            if ((CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4) &&  !mf_info->multi_vnics_mode)
            {
                u8_t other_port = !PORT_ID(pdev);
                u8_t abs_func_on_other_port = PATH_ID(pdev) + 2*other_port;
                LM_SHMEM_READ(pdev, NO_MCP_WA_OVLAN(abs_func_on_other_port), &val);

                mf_info->path_has_ovlan = VALID_OVLAN((u16_t)val) ? 1 : 0;
            }

            /* For simplicity, we leave vnics_per_port to be 2, for resource splitting issues... */
            if (mf_info->path_has_ovlan)
            {
                if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
                {
                    mf_info->vnics_per_port = 2;
                }
                else
                {
                    mf_info->vnics_per_port = 4;
                }
            }

            /* If we're multi-vnic, we'll set a default mf_mode of switch-dependent, this could be overriden
             * later on by registry */
            mf_info->mf_mode = MULTI_FUNCTION_SD;

        }
        lm_status = lm_get_shmem_license_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }
    /* sanity checks on vnic params */
    if (mf_info->multi_vnics_mode)
    {
        if (!VALID_OVLAN(mf_info->ext_id))
        {
            DbgMessage(pdev, FATAL, "Invalid ovlan (0x%x) configured for Func %d. Can't load the function.\n",
                        mf_info->ext_id, ABS_FUNC_ID(pdev));
            lm_status = LM_STATUS_FAILURE;
        }
    }
    if ((mf_info->vnics_per_port - 1 < VNIC_ID(pdev)) || ( !mf_info->multi_vnics_mode && (VNIC_ID(pdev) > 0)))
    {
        DbgMessage(pdev, FATAL, "Invalid vnics_per_port (%d) configured for Func %d. Can't load the function.\n",
                    mf_info->vnics_per_port, ABS_FUNC_ID(pdev));
        lm_status = LM_STATUS_FAILURE;
    }
    return lm_status;
}



static lm_status_t lm_get_shmem_shared_hw_config(lm_device_t *pdev)
{
    u32_t val = 0;
    u8_t  i   = 0;

    /* Get the hw config words. */
    LM_SHMEM_READ(pdev, OFFSETOF(shmem_region_t, dev_info.shared_hw_config.config),&val);
    pdev->hw_info.nvm_hw_config = val;
    pdev->params.link.hw_led_mode = ((pdev->hw_info.nvm_hw_config & SHARED_HW_CFG_LED_MODE_MASK) >> SHARED_HW_CFG_LED_MODE_SHIFT);
    DbgMessage(pdev, INFORMi, "nvm_hw_config %d\n",val);

    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t, dev_info.shared_hw_config.config2),&val);
    pdev->hw_info.nvm_hw_config2 = val;
    DbgMessage(pdev, INFORMi, "nvm_hw_configs %d\n",val);

    //board_sn;
    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t, dev_info.shared_hw_config.part_num),&val);
    pdev->hw_info.board_num[0] = (u8_t) val;
    pdev->hw_info.board_num[1] = (u8_t) (val >> 8);
    pdev->hw_info.board_num[2] = (u8_t) (val >> 16);
    pdev->hw_info.board_num[3] = (u8_t) (val >> 24);

    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t, dev_info.shared_hw_config.part_num)+4,&val);
    pdev->hw_info.board_num[4] = (u8_t) val;
    pdev->hw_info.board_num[5] = (u8_t) (val >> 8);
    pdev->hw_info.board_num[6] = (u8_t) (val >> 16);
    pdev->hw_info.board_num[7] = (u8_t) (val >> 24);

    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t, dev_info.shared_hw_config.part_num)+8,&val);
    pdev->hw_info.board_num[8] = (u8_t) val;
    pdev->hw_info.board_num[9] = (u8_t) (val >> 8);
    pdev->hw_info.board_num[10] =(u8_t) (val >> 16);
    pdev->hw_info.board_num[11] =(u8_t) (val >> 24);

    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t, dev_info.shared_hw_config.part_num)+12,&val);
    pdev->hw_info.board_num[12] = (u8_t) val;
    pdev->hw_info.board_num[13] = (u8_t) (val >> 8);
    pdev->hw_info.board_num[14] = (u8_t) (val >> 16);
    pdev->hw_info.board_num[15] = (u8_t) (val >> 24);
    DbgMessage(pdev, INFORMi, "board_sn: ");
    for (i = 0 ; i < 16 ; i++ )
    {
        DbgMessage(pdev, INFORMi, "%02x",pdev->hw_info.board_num[i]);
    }
    DbgMessage(pdev, INFORMi, "\n");

    /* Get the override preemphasis flag */
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.shared_feature_config.config),&val);
    if GET_FLAGS(val, SHARED_FEAT_CFG_OVERRIDE_PREEMPHASIS_CFG_ENABLED)
    {
        SET_FLAGS( pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED);
    }
    else
    {
        RESET_FLAGS(pdev->params.link.feature_config_flags,ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED);
    }
#ifdef EDIAG
    /* Diag doesn't support remote fault detection */
    SET_FLAGS( pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_DISABLE_REMOTE_FAULT_DET);
    /* Only Diag supports IEEE PHY testing */
    SET_FLAGS( pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_IEEE_PHY_TEST);
#endif
    return LM_STATUS_SUCCESS;
}

static u32_t lm_get_shmem_mf_cfg_base(lm_device_t *pdev)
{
    u32_t shmem2_size;
    u32_t offset;
    u32_t mf_cfg_offset_value;

    offset = pdev->hw_info.shmem_base + OFFSETOF(shmem_region_t, func_mb) + E1H_FUNC_MAX * sizeof(struct drv_func_mb);
    if (pdev->hw_info.shmem_base2 != 0)
    {
        LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,size), &shmem2_size);
        if (shmem2_size > OFFSETOF(shmem2_region_t,mf_cfg_addr))
        {
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,mf_cfg_addr), &mf_cfg_offset_value);
            if (SHMEM_MF_CFG_ADDR_NONE != mf_cfg_offset_value)
            {
                offset = mf_cfg_offset_value;
            }
        }
    }
    return offset;
}

static lm_status_t lm_get_shmem_port_hw_config(lm_device_t *pdev)
{
    u32_t val;
    const u8_t port = PORT_ID(pdev);

    /* mba features*/
    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].mba_config),
        &val);
    pdev->hw_info.mba_features = (val & PORT_FEATURE_MBA_BOOT_AGENT_TYPE_MASK);
    DbgMessage(pdev, INFORMi, "mba_features %d\n",pdev->hw_info.mba_features);
    /* mba_vlan_cfg */
    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].mba_vlan_cfg),
        &val);
    pdev->hw_info.mba_vlan_cfg = val ;
    DbgMessage(pdev, INFORMi, "mba_vlan_cfg 0x%x\n",pdev->hw_info.mba_vlan_cfg);

    // port_feature_config bits
    LM_SHMEM_READ(pdev,
        OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].config),
        &val);
    pdev->hw_info.port_feature_config = val;
    DbgMessage(pdev, INFORMi, "port_feature_config 0x%x\n",pdev->hw_info.port_feature_config);

#ifndef DOS
    /* AutogrEEEn settings */
    if(val & PORT_FEAT_CFG_AUTOGREEEN_ENABLED) {
        SET_FLAGS( pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_AUTOGREEEN_ENABLED);
    } else {
        RESET_FLAGS( pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_AUTOGREEEN_ENABLED);
    }
#endif
    /* clc params*/
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[port].speed_capability_mask),&val);
    pdev->params.link.speed_cap_mask[0] = val & PORT_HW_CFG_SPEED_CAPABILITY_D0_MASK;
    DbgMessage(pdev, INFORMi, "speed_cap_mask1 %d\n",val);

    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[port].speed_capability_mask2),&val);
    pdev->params.link.speed_cap_mask[1] = val & PORT_HW_CFG_SPEED_CAPABILITY_D0_MASK;
    DbgMessage(pdev, INFORMi, "speed_cap_mask2 %d\n",val);

    /* Get lane swap*/
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[port].lane_config),&val);
    pdev->params.link.lane_config = val;
    DbgMessage(pdev, INFORMi, "lane_config %d\n",val);

    /*link config  */
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].link_config),&val);
    pdev->hw_info.link_config[ELINK_INT_PHY] = val;
    pdev->params.link.switch_cfg = val & PORT_FEATURE_CONNECTED_SWITCH_MASK;
    DbgMessage(pdev, INFORMi, "link config %d\n",val);

    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].link_config2),&val);
    pdev->hw_info.link_config[ELINK_EXT_PHY1] = val;

    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[port].multi_phy_config),&val);
    /* set the initial value to the link params */
    pdev->params.link.multi_phy_config = val;
    /* save the initial value if we'll want to restore it later */
    pdev->hw_info.multi_phy_config = val;
    /* check if 10g KR is blocked on this session */
    pdev->hw_info.no_10g_kr = FALSE ;

    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[port].default_cfg),&val);
    pdev->hw_info.phy_force_kr_enabler = (val & PORT_HW_CFG_FORCE_KR_ENABLER_MASK) ;

    /* If the force KR enabler is on, 10G/20G should have been enabled in the
     * nvram as well. If 10G/20G capbility is not set, it means that the MFW
     * disabled it and we should set the no_10g_kr flag */
    if(( PORT_HW_CFG_FORCE_KR_ENABLER_NOT_FORCED != pdev->hw_info.phy_force_kr_enabler ) &&
        ( FALSE == ( pdev->params.link.speed_cap_mask[0] & (PORT_HW_CFG_SPEED_CAPABILITY_D0_10G | PORT_HW_CFG_SPEED_CAPABILITY_D0_20G))) )
    {
        pdev->hw_info.no_10g_kr = TRUE ;
    }

    /* read EEE mode from shmem (original source is NVRAM) */
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].eee_power_mode),&val);
    pdev->params.link.eee_mode = val & PORT_FEAT_CFG_EEE_POWER_MODE_MASK;
    DbgMessage(pdev, INFORMi, "eee_power_mode 0x%x\n", pdev->params.link.eee_mode);

    if ((pdev->params.link.eee_mode & PORT_FEAT_CFG_EEE_POWER_MODE_MASK) != PORT_FEAT_CFG_EEE_POWER_MODE_DISABLED)
    {
        SET_FLAGS(pdev->params.link.eee_mode,
                              ELINK_EEE_MODE_ENABLE_LPI |
                              ELINK_EEE_MODE_ADV_LPI);
    }

    return LM_STATUS_SUCCESS;
}

/* Check if other path is in multi_function_mode */
static void lm_set_path_has_ovlan(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;
    u32_t                  val     = 0;

    mf_info->path_has_ovlan = FALSE;

    if (mf_info->mf_mode == MULTI_FUNCTION_SD)
    {
        mf_info->path_has_ovlan = TRUE;
    }
    else if (mf_info->mf_mode == SINGLE_FUNCTION)
    {
        /* decide on path multi vnics mode - incase we're not in mf mode...and in 4-port-mode good enough to check vnic-0 of the other port, on the same path */
        if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
        {
            u8_t other_port = !PORT_ID(pdev);
            u8_t abs_func_on_other_port = PATH_ID(pdev) + 2*other_port;
            LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[abs_func_on_other_port].e1hov_tag),&val);

            mf_info->path_has_ovlan = VALID_OVLAN((u16_t)val) ? 1 : 0;
        }
    }
}

/**
 * @Description
 *    Initializes mf mode and data, checks that mf info is valid
 *  by checking that MAC address must be legal (check only upper
 *    bytes) for  Switch-Independent mode;
 *    OVLAN must be legal for Switch-Dependent mode
 *
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t lm_get_shmem_mf_cfg_info(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;
    u32_t val                      = 0;
    u32_t val2                     = 0;
    u32_t mac_upper                = 0;
    lm_status_t status = LM_STATUS_SUCCESS;

    /* Set some mf_info defaults */
    mf_info->vnics_per_port   = 1;
    mf_info->multi_vnics_mode = FALSE;
    mf_info->path_has_ovlan   = FALSE;
    mf_info->mf_mode          = SINGLE_FUNCTION;
    pdev->params.mf_proto_support_flags = 0;
    

    /* Get the multi-function-mode value (switch dependent / independent / single-function )  */
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.shared_feature_config.config),&val);
    val &= SHARED_FEAT_CFG_FORCE_SF_MODE_MASK;

    switch (val)
    {
    case SHARED_FEAT_CFG_FORCE_SF_MODE_SWITCH_INDEPT:
        LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].mac_upper),&mac_upper);
        /* check for legal mac (upper bytes)*/
        if (mac_upper != FUNC_MF_CFG_UPPERMAC_DEFAULT)
        {
            mf_info->mf_mode = MULTI_FUNCTION_SI;
        }
        else
        {
            DbgMessage(pdev, WARNi, "Illegal configuration for switch independent mode\n");
        }
        DbgBreakIf(CHIP_IS_E1x(pdev));
        break;
    case SHARED_FEAT_CFG_FORCE_SF_MODE_MF_ALLOWED:
    case SHARED_FEAT_CFG_FORCE_SF_MODE_SPIO4:
        /* get OV configuration */
        LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].e1hov_tag),&val);
        val &= FUNC_MF_CFG_E1HOV_TAG_MASK;

        if (val != FUNC_MF_CFG_E1HOV_TAG_DEFAULT)
        {
            mf_info->mf_mode = MULTI_FUNCTION_SD;
            mf_info->sd_mode = SD_REGULAR_MODE;
        }
        else
        {
            DbgMessage(pdev, WARNi, "Illegal configuration for switch dependent mode\n");
        }
        break;
    case SHARED_FEAT_CFG_FORCE_SF_MODE_FORCED_SF:
        /* We're not in multi-function mode - return with vnics_per_port=1 & multi_vnics_mode = FALSE*/
        return LM_STATUS_SUCCESS;
    case SHARED_FEAT_CFG_FORCE_SF_MODE_AFEX_MODE:
        /* mark mf mode as NIV if MCP version includes NPAR-SD support
           and the MAC address is valid.
         */
        LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].mac_upper),&mac_upper);
        if ((LM_SHMEM2_HAS(pdev, afex_driver_support)) &&
            (mac_upper != FUNC_MF_CFG_UPPERMAC_DEFAULT) )
        {
            mf_info->mf_mode = MULTI_FUNCTION_AFEX;
        }
        else
        {
            DbgMessage(pdev, WARNi, "Illegal configuration for NPAR-SD mode\n");
        }
        DbgBreakIf(CHIP_IS_E1x(pdev));
        break;
    case SHARED_FEAT_CFG_FORCE_SF_MODE_BD_MODE:
        mf_info->mf_mode = MULTI_FUNCTION_SD;
        mf_info->sd_mode = SD_BD_MODE;
        DbgMessage(pdev, WARN, "lm_get_shmem_info: SF_MODE_BD_MODE is detected.\n");
        break;

    case SHARED_FEAT_CFG_FORCE_SF_MODE_UFP_MODE:
        mf_info->mf_mode = MULTI_FUNCTION_SD;
        mf_info->sd_mode = SD_UFP_MODE;
        DbgMessage(pdev, WARN, "lm_get_shmem_info: SF_MODE_UFP_MODE is detected.\n");
        break;

    case SHARED_FEAT_CFG_FORCE_SF_MODE_EXTENDED_MODE:
        /* Get extended mf mode value */
        LM_SHMEM_READ(pdev, OFFSETOF(shmem_region_t, dev_info.shared_hw_config.config_3),&val);
        val2 &= SHARED_HW_CFG_EXTENDED_MF_MODE_MASK;
        switch (val2)
        {
        case SHARED_HW_CFG_EXTENDED_MF_MODE_NPAR1_DOT_5:
            mf_info->mf_mode = MULTI_FUNCTION_SI;
            break;

        default:
            DbgBreakMsg(" Unknown extended mf mode\n");
            return LM_STATUS_FAILURE;
        }
        break;

    default:
        DbgBreakMsg(" Unknown mf mode\n");
        return LM_STATUS_FAILURE;
    }

    /* Set path mf_mode (which could be different than function mf_mode)  */
    lm_set_path_has_ovlan(pdev);

    /* Invalid Multi function configuration: */
    if (mf_info->mf_mode == SINGLE_FUNCTION)
    {
        if (VNIC_ID(pdev) >= 1)
        {
            return LM_STATUS_FAILURE;
        }
        return LM_STATUS_SUCCESS;
    }

    /* Get the multi-function configuration */
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].config),&val);
    mf_info->func_mf_cfg = val;

    switch(mf_info->mf_mode)
    {
        case MULTI_FUNCTION_SD:
        {
            switch (mf_info->sd_mode) 
            {
                case SD_REGULAR_MODE:
                    status = lm_get_shmem_mf_cfg_info_sd(pdev);
                    break;
                case SD_UFP_MODE:
                    status = lm_get_shmem_mf_cfg_info_sd_ufp(pdev);
                    break;
                case SD_BD_MODE:
                    status = lm_get_shmem_mf_cfg_info_sd_bd(pdev);
                    break;
                default:
                    DbgBreak();
            }

            if(status != LM_STATUS_SUCCESS)
                return status;
        }
        break;
        case MULTI_FUNCTION_SI:
        {
            lm_get_shmem_mf_cfg_info_si(pdev);
        }
        break;
        case MULTI_FUNCTION_AFEX:
        {
            lm_get_shmem_mf_cfg_info_niv(pdev);
        }
        break;
        default:
        {
            DbgBreakIfAll(TRUE);
            return LM_STATUS_FAILURE;
        }
    }

    lm_cmng_get_shmem_info(pdev);

    return lm_check_valid_mf_cfg(pdev);
}

static void lm_fcoe_set_default_wwns(lm_device_t *pdev)
{
    /* create default wwns from fcoe mac adress */
    mm_memcpy(&(pdev->hw_info.fcoe_wwn_port_name[2]), pdev->hw_info.fcoe_mac_addr, 6);
    pdev->hw_info.fcoe_wwn_port_name[0] = 0x20;
    pdev->hw_info.fcoe_wwn_port_name[1] = 0;
    mm_memcpy(&(pdev->hw_info.fcoe_wwn_node_name[2]), pdev->hw_info.fcoe_mac_addr, 6);
    pdev->hw_info.fcoe_wwn_node_name[0] = 0x10;
    pdev->hw_info.fcoe_wwn_node_name[1] = 0;
}

static lm_status_t lm_get_shmem_mf_mac_info(lm_device_t *pdev)
{
    lm_hardware_mf_info_t *mf_info   = &pdev->hw_info.mf_info;
    u32_t                  mac_upper = 0;
    u32_t                  mac_lower = 0;

    if (mf_info->mf_mode == SINGLE_FUNCTION)
    {
        return LM_STATUS_FAILURE;
    }

    /* Get the permanent L2 MAC address. */
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].mac_upper),&mac_upper);
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].mac_lower),&mac_lower);


    /* Mac validity is assumed since we already checked it to determine mf_mode. And we assume mf_mode
     * is configured correctly when we enter this function. */
    SET_FLAGS(mf_info->flags,MF_INFO_VALID_MAC);
    _copy_mac_upper_lower_to_arr(mac_upper, mac_lower, pdev->hw_info.mac_addr);

    /* Set iSCSI / FCOE Mac addresses */
    switch (mf_info->mf_mode)
    {
    case MULTI_FUNCTION_SD:
        {
            // in E1x the ext mac doesn't exists and will cause MCP parity error CQ67469
            if ( CHIP_IS_E1x(pdev) || IS_SD_UFP_MODE(pdev) || IS_SD_BD_MODE(pdev))
            {
                /* Set all iscsi and fcoe mac addresses the same as network. */
                mm_memcpy(pdev->hw_info.iscsi_mac_addr, pdev->hw_info.mac_addr, 6);
                mm_memcpy(pdev->hw_info.fcoe_mac_addr,  pdev->hw_info.mac_addr, 6);
                break;
            }
        }
    case MULTI_FUNCTION_SI:
    case MULTI_FUNCTION_AFEX:
        lm_get_shmem_ext_mac_addresses(pdev);
        break;
    }

    return LM_STATUS_SUCCESS;
}

static lm_status_t lm_get_shmem_sf_mac_info(lm_device_t *pdev)
{
    u32_t val  = 0;
    u32_t val2 = 0;

    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t, dev_info.port_hw_config[PORT_ID(pdev)].mac_upper),&val);
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t, dev_info.port_hw_config[PORT_ID(pdev)].mac_lower),&val2);
    _copy_mac_upper_lower_to_arr(val, val2, pdev->hw_info.mac_addr);

    /* Get iSCSI MAC address. */
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].iscsi_mac_upper),&val);
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].iscsi_mac_lower),&val2);
    _copy_mac_upper_lower_to_arr(val, val2, pdev->hw_info.iscsi_mac_addr);

     /* Get FCoE MAC addresses. */
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].fcoe_fip_mac_upper),&val);
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].fcoe_fip_mac_lower),&val2);
    _copy_mac_upper_lower_to_arr(val, val2, pdev->hw_info.fcoe_mac_addr);

    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].fcoe_wwn_port_name_upper),&val);
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].fcoe_wwn_port_name_lower),&val2);
    _copy_mac_upper_lower_to_arr(val, val2, &(pdev->hw_info.fcoe_wwn_port_name[2]));
    pdev->hw_info.fcoe_wwn_port_name[0] = (u8_t) (val >> 24);
    pdev->hw_info.fcoe_wwn_port_name[1] = (u8_t) (val >> 16);

    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].fcoe_wwn_node_name_upper),&val);
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].fcoe_wwn_node_name_lower),&val2);
    _copy_mac_upper_lower_to_arr(val, val2, &(pdev->hw_info.fcoe_wwn_node_name[2]));
    pdev->hw_info.fcoe_wwn_node_name[0] = (u8_t) (val >> 24);
    pdev->hw_info.fcoe_wwn_node_name[1] = (u8_t) (val >> 16);

    DbgMessage(pdev, INFORMi, "main mac addr: %02x %02x %02x %02x %02x %02x\n",
        pdev->hw_info.mac_addr[0],
        pdev->hw_info.mac_addr[1],
        pdev->hw_info.mac_addr[2],
        pdev->hw_info.mac_addr[3],
        pdev->hw_info.mac_addr[4],
        pdev->hw_info.mac_addr[5]);
    DbgMessage(pdev, INFORMi, "iSCSI mac addr: %02x %02x %02x %02x %02x %02x\n",
        pdev->hw_info.iscsi_mac_addr[0],
        pdev->hw_info.iscsi_mac_addr[1],
        pdev->hw_info.iscsi_mac_addr[2],
        pdev->hw_info.iscsi_mac_addr[3],
        pdev->hw_info.iscsi_mac_addr[4],
        pdev->hw_info.iscsi_mac_addr[5]);

    return LM_STATUS_SUCCESS;
}

/* Gets the sriov info from shmem of ALL functions and marks if configuration is assymetric */
static void lm_get_shmem_sf_sriov_info(lm_device_t *pdev)
{
    const lm_chip_port_mode_t port_mode         = CHIP_PORT_MODE(pdev);
    u32_t                     offset            = 0;
    u32_t                     val               = 0;
    u8_t                      port_max          = (port_mode == LM_CHIP_PORT_MODE_2)? 1 : PORT_MAX;
    const u8_t                port              = PORT_ID(pdev);
    u8_t                      port_idx          = 0;
    u8_t                      sriov_enabled     = 0xff;
    u8_t                      sriov_disabled    = 0xff;

    ASSERT_STATIC((FIELD_SIZE(struct shm_dev_info, port_hw_config)/FIELD_SIZE(struct shm_dev_info, port_hw_config[0])) >= max(PORT_MAX,1));

    if (CHIP_IS_E1x(pdev))
    {
        pdev->hw_info.sriov_info.shmem_num_vfs_in_pf = 0;
        pdev->hw_info.sriov_info.b_pf_asymetric_configuration = FALSE;

        return;
    }

    for (port_idx = 0; port_idx < port_max; port_idx++)
    {
        offset = OFFSETOF(shmem_region_t,dev_info.port_hw_config[port_idx].pf_allocation);
        LM_SHMEM_READ(pdev, offset, &val);

        val = (val & PORT_HW_CFG_NUMBER_OF_VFS_MASK) >> PORT_HW_CFG_NUMBER_OF_VFS_SHIFT;

        if (0 == val)
        {
            sriov_disabled = 1;
        }
        else
        {
            sriov_enabled = 1;
        }

        if (port_idx == port)
        {
            pdev->hw_info.sriov_info.shmem_num_vfs_in_pf = val;
        }
    }


    /* check if assymteric configuration...basically we initialize both params to 0xff, so the only way they can both be
     * the same is if one of the ports was enabled and one was disabled... */
    if (sriov_disabled == sriov_enabled)
    {
        pdev->hw_info.sriov_info.b_pf_asymetric_configuration = TRUE;
    }
    else
    {
        pdev->hw_info.sriov_info.b_pf_asymetric_configuration = FALSE;
    }

}

static void lm_get_shmem_mf_sriov_info(lm_device_t *pdev)
{
    u32_t                     offset               = 0;
    u32_t                     val                  = 0;
    u8_t                      func                 = 0;
    const u8_t                abs_func             = ABS_FUNC_ID(pdev);
    u8_t                      abs_func_idx         = 0;
    u8_t                      sriov_enabled        = 0xff;
    u8_t                      sriov_disabled       = 0xff;

    ASSERT_STATIC((FIELD_SIZE(struct mf_cfg, func_mf_config) / FIELD_SIZE(struct mf_cfg, func_mf_config[0])) == E2_FUNC_MAX*2);

    if (CHIP_IS_E1x(pdev))
    {
        pdev->hw_info.sriov_info.shmem_num_vfs_in_pf = 0;
        pdev->hw_info.sriov_info.b_pf_asymetric_configuration = FALSE;

        return;
    }

    for (func = 0; func < E2_FUNC_MAX; func++)
    {
        abs_func_idx = PATH_ID(pdev) + func*2;

        offset = OFFSETOF(mf_cfg_t, func_mf_config[abs_func_idx].pf_allocation);
        LM_MFCFG_READ(pdev, offset,&val);
        val = (val & FUNC_MF_CFG_NUMBER_OF_VFS_MASK) >> FUNC_MF_CFG_NUMBER_OF_VFS_SHIFT;

        if (0 == val)
        {
            sriov_disabled = 1;
        }
        else
        {
            sriov_enabled = 1;
        }

        if (abs_func_idx == abs_func)
        {
            pdev->hw_info.sriov_info.shmem_num_vfs_in_pf = val;
        }
    }


    /* check if assymteric configuration...basically we initialize both params to 0xff, so the only way they can both be
     * the same is if one of the ports was enabled and one was disabled... */
    if (sriov_disabled == sriov_enabled)
    {
        pdev->hw_info.sriov_info.b_pf_asymetric_configuration = TRUE;
    }
    else
    {
        pdev->hw_info.sriov_info.b_pf_asymetric_configuration = FALSE;
    }

}


static lm_status_t lm_get_shmem_mac_info(lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    if (pdev->hw_info.mf_info.mf_mode == SINGLE_FUNCTION)
    {
        lm_status = lm_get_shmem_sf_mac_info(pdev);
    }
    else
    {
        lm_status = lm_get_shmem_mf_mac_info(pdev);
    }

    return lm_status;
}

static void lm_get_shmem_sriov_info(lm_device_t *pdev)
{
    const u32_t bc_rev    = LM_GET_BC_REV_MAJOR(pdev);

    if (CHIP_IS_E1x(pdev) || (bc_rev < BC_REV_IE_SRIOV_SUPPORTED))
    {
        return;
    }

    if (pdev->hw_info.mf_info.mf_mode == SINGLE_FUNCTION)
    {
        lm_get_shmem_sf_sriov_info(pdev);
    }
    else
    {
        lm_get_shmem_mf_sriov_info(pdev);
    }
}

static void lm_get_shmem_fw_flow_control(lm_device_t *pdev)
{
    u32_t func_ext_cfg = 0;

    // cq57766
    // if this static assert fails consider adding the new mode to the if
    // and read the l2_fw_flow_ctrl from the shmem in the new mode also
    ASSERT_STATIC(MAX_MF_MODE == 4);
    // l2_fw_flow_ctrl is read from the shmem in multi-function mode in E2 and above.
    // In all other cases this parameter is read from the registry.
    // We read this parameter from the registry in E1.5 multi-function since 57711 boot code does not have the struct func_ext_cfg
    if (((pdev->hw_info.mf_info.mf_mode == MULTI_FUNCTION_SI)   ||
         (pdev->hw_info.mf_info.mf_mode == MULTI_FUNCTION_AFEX)) &&
        (!CHIP_IS_E1x(pdev)))
    {
        LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_ext_config[ABS_FUNC_ID(pdev)].func_cfg), &func_ext_cfg);
        if (GET_FLAGS(func_ext_cfg, MACP_FUNC_CFG_PAUSE_ON_HOST_RING))
        {
            pdev->params.l2_fw_flow_ctrl = 1;
        }
        else
        {
            pdev->params.l2_fw_flow_ctrl = 0;
        }
    }
}

/**
 * @Description
 *     This function is responsible for reading all the data
 *     that the driver needs before loading from the shmem.
 *
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t lm_get_shmem_info(lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t       val       = 0;

    lm_shmem_set_default(pdev);

    val = lm_get_shmem_base_addr(pdev);
    if (!val)
    {
        DbgMessage(pdev, WARNi, "NO MCP\n");
        return lm_get_shmem_info_no_mcp_bypass(pdev);
    }

    pdev->hw_info.mcp_detected = 1;
    pdev->hw_info.shmem_base   = val;

    pdev->hw_info.shmem_base2 = REG_RD(pdev, PATH_ID(pdev) ? MISC_REG_GENERIC_CR_1 : MISC_REG_GENERIC_CR_0);
    pdev->hw_info.mf_cfg_base = lm_get_shmem_mf_cfg_base(pdev);

    DbgMessage(pdev, WARNi, "MCP Up Detected. shmem_base=0x%x shmem_base2=0x%x mf_cfg_offset=0x%x\n",
                pdev->hw_info.shmem_base, pdev->hw_info.shmem_base2, pdev->hw_info.mf_cfg_base);

    lm_status = lm_verify_validity_map( pdev );
    if(LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, FATAL, "lm_get_shmem_info: Shmem signature not present.\n");
        pdev->hw_info.mcp_detected = 0;
        return LM_STATUS_SUCCESS;
     }

    /* bc rev */
    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.bc_rev),&val);
    pdev->hw_info.bc_rev = val;
    DbgMessage(pdev, INFORMi, "bc_rev %d\n",val);

    lm_status = lm_get_shmem_shared_hw_config(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, WARNi, "lm_get_shmem_shared_hw_config returned lm_status=%d\n", lm_status);
        return lm_status;
    }

    lm_status = lm_get_shmem_port_hw_config(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, WARNi, "lm_get_shmem_port_hw_config returned lm_status=%d\n", lm_status);
        return lm_status;
    }

    /* Check License for toe/rdma/iscsi */
#ifdef _LICENSE_H
    lm_status = lm_get_shmem_license_info(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, WARNi, "lm_get_shmem_license_info returned lm_status=%d\n", lm_status);
        return lm_status;
    }
#endif
    /* get mf config parameters */
    if (IS_MF_MODE_CAPABLE(pdev) && (pdev->hw_info.mf_cfg_base != SHMEM_MF_CFG_ADDR_NONE))
    {
        lm_status = lm_get_shmem_mf_cfg_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARNi, "lm_get_shmem_mf_cfg_info returned lm_status=%d\n", lm_status);
            return lm_status;
        }
    }
    else if (FUNC_ID(pdev) != PORT_ID(pdev))
    {
        DbgMessage(pdev, WARNi, "Illegal to load func %d of port %d on non MF mode capable device\n");
        return LM_STATUS_FAILURE;
    }

    lm_get_shmem_sriov_info(pdev);

    lm_status = lm_get_shmem_mac_info(pdev);

    lm_get_shmem_fw_flow_control(pdev);

    return lm_status;
}

void init_link_params(lm_device_t *pdev)
{
    u32_t val              = 0;
    u32_t feat_val         = 0;
    const u8_t port     = PORT_ID(pdev);

    pdev->params.link.port        = port;
    pdev->params.link.lfa_base = 0;
    pdev->params.link.shmem_base = NO_MCP_WA_CLC_SHMEM;
    pdev->params.link.shmem2_base= NO_MCP_WA_CLC_SHMEM;

    if (pdev->hw_info.mcp_detected)
    {
        pdev->params.link.shmem_base = pdev->hw_info.shmem_base;
        pdev->params.link.shmem2_base= pdev->hw_info.shmem_base2;

        // Only if LFA is supported in MFW
        if (LM_SHMEM2_HAS(pdev,lfa_host_addr[port]))
        {
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t, lfa_host_addr[port]), &pdev->params.link.lfa_base);
        }
   }

    pdev->params.link.chip_id = pdev->hw_info.chip_id;
    pdev->params.link.cb      = pdev;

    ///TODO remove - the initialization in lm_mcp_cmd_init should be enough, but BC versions are still in flux.
    if(pdev->hw_info.mf_info.mf_mode == MULTI_FUNCTION_AFEX) //we can't use IS_MF_NIV_MODE because params.mf_mode is not initalized yet.
    {
        SET_FLAGS( pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_BC_SUPPORTS_AFEX );
    }

    if (CHIP_REV_IS_SLOW(pdev))
    {
        val = CHIP_BONDING(pdev);
        DbgMessage(pdev, WARN, "init_link_params: chip bond id is 0x%x\n",val);

        if (pdev->hw_info.chip_port_mode == LM_CHIP_PORT_MODE_4)
        {
            feat_val |= ELINK_FEATURE_CONFIG_EMUL_DISABLE_BMAC;
        }
        else if (val & 0x4)
        {
            // force to work with emac
            if (CHIP_IS_E3(pdev))
            {
                pdev->params.link.req_line_speed[0] = ELINK_SPEED_1000;
                feat_val |= ELINK_FEATURE_CONFIG_EMUL_DISABLE_XMAC;
            }
            else
            {
                feat_val |= ELINK_FEATURE_CONFIG_EMUL_DISABLE_BMAC;
            }
        }
        else if (val & 0x8)
        {
            if (CHIP_IS_E3(pdev))
            {
                feat_val |= ELINK_FEATURE_CONFIG_EMUL_DISABLE_UMAC;
            }
            else
            {
                feat_val |= ELINK_FEATURE_CONFIG_EMUL_DISABLE_EMAC;
            }
        }
        /* Disable EMAC for E3 and above */
        if (val & 2)
        {
            feat_val |= ELINK_FEATURE_CONFIG_EMUL_DISABLE_EMAC;
        }

        SET_FLAGS(pdev->params.link.feature_config_flags, feat_val);
    }
}

/** lm_init_cam_params
 *  set cam/mac parameters
 *
 *  cam mapping is dynamic, we only set sizes...
 *
 */
static void lm_init_cam_params(lm_device_t *pdev)
{
    /* FIXME: remove once constants are in hsi file */
    #define LM_CAM_SIZE_EMUL                    (5)                                /*5 per vnic also in single function mode (real cam size on emulation is 20 per port) */
    #define LM_MC_TABLE_SIZE_EMUL               (1)
    #define LM_CAM_SIZE_EMUL_E2                 (40)

    u16_t mc_credit;
    u16_t uc_credit;
    u8_t b_is_asic = CHIP_REV_IS_ASIC(pdev);
    u8_t num_ports = 2;
    u8_t num_funcs;

    /* set CAM parameters according to EMUL/FPGA or ASIC + Chip*/
    mm_mem_zero(pdev->params.uc_table_size, sizeof(pdev->params.uc_table_size));
    mm_mem_zero(pdev->params.mc_table_size, sizeof(pdev->params.mc_table_size));

    if (CHIP_IS_E1(pdev))
    {
        pdev->params.cam_size = b_is_asic? MAX_MAC_CREDIT_E1 / num_ports : LM_CAM_SIZE_EMUL;

        mc_credit = b_is_asic? LM_MC_NDIS_TABLE_SIZE : LM_MC_TABLE_SIZE_EMUL;
        uc_credit = pdev->params.cam_size - mc_credit; /* E1 multicast is in CAM */

    /* init unicast table entires */
    pdev->params.uc_table_size[LM_CLI_IDX_ISCSI]    = 1;
        pdev->params.uc_table_size[LM_CLI_IDX_NDIS]  = uc_credit - 1; /* - one for iscsi... */

    /* init multicast table entires */
        pdev->params.mc_table_size[LM_CLI_IDX_NDIS] = mc_credit;

        DbgMessage(pdev, INFORMi, "uc_table_size[ndis]=%d, uc_table_size[ndis]=%d, mc_table_size[ndis]=%d\n",
                   pdev->params.uc_table_size[LM_CLI_IDX_NDIS], pdev->params.uc_table_size[LM_CLI_IDX_ISCSI],
                   pdev->params.mc_table_size[LM_CLI_IDX_NDIS]);

    }
    else if (CHIP_IS_E1H(pdev))
    {
        pdev->params.cam_size = b_is_asic? MAX_MAC_CREDIT_E1H / num_ports: LM_CAM_SIZE_EMUL;
        pdev->params.cam_size = pdev->params.cam_size / pdev->params.vnics_per_port;
        uc_credit = pdev->params.cam_size;

        /* init unicast table entires */
        pdev->params.uc_table_size[LM_CLI_IDX_ISCSI] = 1;
        pdev->params.uc_table_size[LM_CLI_IDX_NDIS]  = uc_credit - 1; /* - one for iscsi... */

        /* init multicast table entires */
        pdev->params.mc_table_size[LM_CLI_IDX_NDIS] = LM_MC_NDIS_TABLE_SIZE;

        DbgMessage(pdev, INFORMi, "uc_table_size[ndis]=%d, uc_table_size[ndis]=%d, mc_table_size[ndis]=%d\n",
                   pdev->params.uc_table_size[LM_CLI_IDX_NDIS], pdev->params.uc_table_size[LM_CLI_IDX_ISCSI],
                   pdev->params.mc_table_size[LM_CLI_IDX_NDIS]);
    }
    else if (CHIP_IS_E2E3(pdev))
    {
        num_ports = (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)? 2 : 1;
    num_funcs = VNICS_PER_PATH(pdev);
    if (num_funcs > 1)
    {
        pdev->params.cam_size = b_is_asic? ((MAX_MAC_CREDIT_E2 - GET_NUM_VFS_PER_PATH(pdev))/ num_funcs + GET_NUM_VFS_PER_PF(pdev)): LM_CAM_SIZE_EMUL_E2;
    }
    else
    {
        pdev->params.cam_size = b_is_asic? MAX_MAC_CREDIT_E2 : LM_CAM_SIZE_EMUL_E2;
    }
        uc_credit = pdev->params.cam_size;

        /* init unicast table entires */
        pdev->params.uc_table_size[LM_CLI_IDX_ISCSI] = 1;
        pdev->params.uc_table_size[LM_CLI_IDX_FCOE]  = 1;
        pdev->params.uc_table_size[LM_CLI_IDX_NDIS]  = uc_credit - 2; /* - the two above... */

        /* init multicast table entires */
        pdev->params.mc_table_size[LM_CLI_IDX_NDIS] = LM_MC_NDIS_TABLE_SIZE;
        pdev->params.mc_table_size[LM_CLI_IDX_FCOE] = LM_MC_FCOE_TABLE_SIZE;

        DbgMessage(pdev, INFORMi, "uc_table_size[ndis]=%d, uc_table_size[ndis]=%d, uc_table_size[fcoe]=%d, mc_table_size[ndis]=%d, mc_table_size[fcoe]=%d\n",
                    pdev->params.uc_table_size[LM_CLI_IDX_NDIS], pdev->params.uc_table_size[LM_CLI_IDX_ISCSI],
                    pdev->params.uc_table_size[LM_CLI_IDX_FCOE],
                    pdev->params.mc_table_size[LM_CLI_IDX_NDIS], pdev->params.mc_table_size[LM_CLI_IDX_FCOE]);
    }
    else
    {
        DbgBreakIfAll("New Chip?? initialize cam params!\n");
    }

    /* override CAM parameters for chips later than E1 */
    if (IS_PFDEV(pdev))
    {
        pdev->params.base_offset_in_cam_table = ((num_ports == 2)? FUNC_ID(pdev) : VNIC_ID(pdev)) * LM_CAM_SIZE(pdev);
    }
    else if (IS_CHANNEL_VFDEV(pdev))
    {
        pdev->params.base_offset_in_cam_table = 0;
        pdev->params.mc_table_size[LM_CLI_IDX_NDIS] = 0; /* Will be filled later on acquire response (HW_CHANNEL)*/
    }
}

/*
 * \brief Initialize pdev->params members
 *
 * This function initializes the various pdev->params members, depending
 * on chip technology/implementation: fpga, emul or asic (default).
 *
 * The function may also be used to validate these parameters.
 *
 * \param[in,out]   pdev
 * \param[in]       validate        flag to indicate desired operation.
 *
 * \return success/failure indication
 */

static lm_status_t lm_init_params(lm_device_t *pdev, u8_t validate)
{
    typedef struct _param_entry_t
    {
        /* Ideally, we want to save the address of the parameter here.
        * However, some compiler will not allow us to dynamically
        * initialize the pointer to a parameter in the table below.
        * As an alternative, we will save the offset to the parameter
        * from pdev device structure. */
        u32_t offset;
        /* Parameter default value. */
        u32_t asic_default;
        u32_t fpga_default;
        u32_t emulation_default;
        /* Limit checking is diabled if min and max are zeros. */
        u32_t min;
        u32_t max;
    } param_entry_t;
    #define _OFFSET(_name)          (OFFSETOF(lm_device_t, params._name))
    #define PARAM_VAL(_pdev, _entry) \
        (*((u32_t *) ((u8_t *) (_pdev) + (_entry)->offset)))
    #define SET_PARAM_VAL(_pdev, _entry, _val) \
        *((u32_t *) ((u8_t *) (_pdev) + (_entry)->offset)) = (_val)
    static param_entry_t param_list[] =
    {
        /*                                 asic     fpga     emul
        offset                          default  default  default min     max */
        { _OFFSET(mtu[LM_CLI_IDX_NDIS]),  9216,    9216,    9216,   1500,   9216 },
        { _OFFSET(mtu[LM_CLI_IDX_ISCSI]),  9216,    9216,    9216,   1500,   9216 },
        { _OFFSET(mtu[LM_CLI_IDX_FCOE]),  9216,    9216,    9216,   1500,   9216 },
//        { _OFFSET(mtu[LM_CLI_IDX_RDMA]),  LM_MTU_INVALID_VALUE,    LM_MTU_INVALID_VALUE,    LM_MTU_INVALID_VALUE,   LM_MTU_INVALID_VALUE,   LM_MTU_INVALID_VALUE },
        { _OFFSET(mtu[LM_CLI_IDX_OOO]),  9216,    9216,    9216,   1500,   9216 },
        { _OFFSET(mtu[LM_CLI_IDX_FWD]),  9216,    9216,    9216,   1500,   9216 },
        { _OFFSET(mtu_max),  9216,    9216,    9216,   1500,   9216 },
        { _OFFSET(rcv_buffer_offset),      0,       0,       0,      0,   9000 },
        { _OFFSET(l2_rx_desc_cnt[LM_CLI_IDX_NDIS]),      200,     200,     200,    0,      32767 },
        { _OFFSET(l2_rx_desc_cnt[LM_CLI_IDX_FCOE]),      200,     200,     200,    0,      32767 },
        { _OFFSET(l2_rx_desc_cnt[LM_CLI_IDX_OOO]),       500,     500,     500,    0,      32767 },
        /* The maximum page count is chosen to prevent us from having
        * more than 32767 pending entries at any one time. */
        { _OFFSET(l2_tx_bd_page_cnt[LM_CLI_IDX_NDIS]),   2,       2,       2,      1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[LM_CLI_IDX_FCOE]),   2,       2,       2,      1,      127 },
        { _OFFSET(l2_tx_coal_buf_cnt[LM_CLI_IDX_NDIS]),  0,       0,       0,      0,      20 },
        { _OFFSET(l2_tx_coal_buf_cnt[LM_CLI_IDX_FCOE]),  0,       0,       0,      0,      20 },
        { _OFFSET(l2_tx_bd_page_cnt[LM_CLI_IDX_FWD]) ,   2,       2,       2,      1,      127 },
        /* NirV: still not supported in ediag, being set in the windows mm */
//        { _OFFSET(l2_rx_desc_cnt[LM_CLI_IDX_ISCSI]),      200,     200,     200,    0,      32767 },
//
//        /* The maximum page count is chosen to prevent us from having
//        * more than 32767 pending entries at any one time. */
//        { _OFFSET(l2_tx_bd_page_cnt[LM_CLI_IDX_ISCSI]),   2,       2,       2,      1,      127 },
//        { _OFFSET(l2_tx_coal_buf_cnt[LM_CLI_IDX_ISCSI]),  0,       0,       0,      0,      20 },
//        { _OFFSET(l2_rx_bd_page_cnt[LM_CLI_IDX_ISCSI]),   1,       1,       1,      1,      127 },
        { _OFFSET(test_mode),              0,       0,       0,      0,      0 },
        { _OFFSET(ofld_cap),               0,       0,       0,      0,      0 },
        { _OFFSET(wol_cap),                0,       0,       0,      0,      0 },
        { _OFFSET(i2c_interval_sec),       0,       0,       0,      0,      1000 },
        { _OFFSET(flow_ctrl_cap),          0,       0,       0,      0,      0x80000000 },
        { _OFFSET(eee_policy),             LM_EEE_CONTROL_NVRAM, LM_EEE_CONTROL_NVRAM, LM_EEE_CONTROL_NVRAM, LM_EEE_CONTROL_HIGH, LM_EEE_CONTROL_NVRAM }, // registry values are 0-5 for this
        { _OFFSET(req_medium),             0xff00,  0x00ff,  0x00ff, 0,   0xfffff },
        { _OFFSET(interrupt_mode),         LM_INT_MODE_INTA, LM_INT_MODE_INTA, LM_INT_MODE_INTA, LM_INT_MODE_INTA, LM_INT_MODE_MIMD},
        { _OFFSET(igu_access_mode),        INTR_BLK_ACCESS_IGUMEM, INTR_BLK_ACCESS_IGUMEM, INTR_BLK_ACCESS_IGUMEM, INTR_BLK_ACCESS_GRC, INTR_BLK_ACCESS_IGUMEM},
        { _OFFSET(sw_config),              4,       4,       4,      0,      4},
        { _OFFSET(selective_autoneg),      0,       0,       0,      0,      0 },
        { _OFFSET(autogreeen),             LM_AUTOGREEEN_NVRAM,       LM_AUTOGREEEN_NVRAM,       LM_AUTOGREEEN_NVRAM,      LM_AUTOGREEEN_DISABLED,      LM_AUTOGREEEN_NVRAM },
        { _OFFSET(wire_speed),             1,       0,       0,      0,      0 },
        { _OFFSET(phy_int_mode),           2,       2,       2,      0,      0 },
        { _OFFSET(link_chng_mode),         2,       2,       2,      0,      0 },
        // TODO add correct values here
        { _OFFSET(max_func_connections),   1024,    1024,    1024,   0,      500000},
#ifdef VF_INVOLVED
        { _OFFSET(max_func_toe_cons),      310,     310,     310,    0,      500000},
#else
        { _OFFSET(max_func_toe_cons),      750,     750,     750,    0,      500000},
#endif
        { _OFFSET(max_func_rdma_cons),     10,       10,      10,    0,      500000},
        { _OFFSET(max_func_iscsi_cons),    128,     128,     128,    0,      500000},
        { _OFFSET(max_func_fcoe_cons),     64,      64,      20,     0,      500000},
        { _OFFSET(context_line_size),      LM_CONTEXT_SIZE,    LM_CONTEXT_SIZE,    LM_CONTEXT_SIZE,   0,      LM_CONTEXT_SIZE },
        { _OFFSET(context_waste_size),     0,       0,       0,      0,      1024 },
        { _OFFSET(num_context_in_page),    4,       4,       4,      0,       128},
        { _OFFSET(client_page_size),       0x1000, 0x1000, 0x1000,0x1000, 0x20000 },
        { _OFFSET(elt_page_size),          0x1000, 0x1000, 0x1000,0x1000, 0x20000 },
        { _OFFSET(ilt_client_page_size),   0x1000, 0x1000, 0x1000,0x1000, 0x20000 },
        { _OFFSET(cfc_last_lcid),          0xff,   0xff,   0xff,    0x1,     0xff },
        { _OFFSET(override_rss_chain_cnt), 0,      0,      0,       0,       16 },
        // network type and max cwnd
        { _OFFSET(network_type),   LM_NETOWRK_TYPE_WAN, LM_NETOWRK_TYPE_WAN, LM_NETOWRK_TYPE_WAN,LM_NETOWRK_TYPE_LAN, LM_NETOWRK_TYPE_WAN },
        { _OFFSET(max_cwnd_wan),   12500000, 12500000, 12500000,12500000, 12500000 },
        { _OFFSET(max_cwnd_lan),   1250000 , 1250000,  1250000, 1250000,  1250000 },
        // cid allocation mode
        { _OFFSET(cid_allocation_mode),     LM_CID_ALLOC_DELAY , LM_CID_ALLOC_DELAY, LM_CID_ALLOC_DELAY,LM_CID_ALLOC_DELAY, LM_CID_ALLOC_NUM_MODES},
        // interrupt coalesing configuration
        { _OFFSET(int_coalesing_mode),      LM_INT_COAL_PERIODIC_SYNC, LM_INT_COAL_NONE, LM_INT_COAL_NONE, 1, LM_INT_COAL_NUM_MODES },
        { _OFFSET(int_per_sec_rx[0]),          5000,    5000,    5000,  1,      200000 },
        { _OFFSET(int_per_sec_rx[1]),          5000,    5000,    5000,  1,      200000 },
        { _OFFSET(int_per_sec_rx[2]),          5000,    5000,    5000,  1,      200000 },
        { _OFFSET(int_per_sec_rx[3]),          5000,    5000,    5000,  1,      200000 },
        { _OFFSET(int_per_sec_tx[0]),          7500,    7500,    7500,  1,      200000 },
        { _OFFSET(int_per_sec_tx[1]),          3800,    3800,    3800,  1,      200000 },
        { _OFFSET(int_per_sec_tx[2]),          3800,    3800,    3800,  1,      200000 },
        { _OFFSET(int_per_sec_tx[3]),          3800,    3800,    3800,  1,      200000 },
        // VF interrupt coalesing configuration
        { _OFFSET(vf_int_per_sec_rx[LM_VF_INT_LOW_IDX]),    5000,    5000,    5000,  1,      200000 },
        { _OFFSET(vf_int_per_sec_rx[LM_VF_INT_MEDIUM_IDX]), 10000,    5000,    5000,  1,      200000 },
        { _OFFSET(vf_int_per_sec_rx[LM_VF_INT_HIGH_IDX]),   20000,    5000,    5000,  1,      200000 },
        { _OFFSET(vf_int_per_sec_tx[LM_VF_INT_LOW_IDX]),    3800,    3800,    3800,  1,      200000 },
        { _OFFSET(vf_int_per_sec_tx[LM_VF_INT_MEDIUM_IDX]), 8000,    3800,    3800,  1,      200000 },
        { _OFFSET(vf_int_per_sec_tx[LM_VF_INT_HIGH_IDX]),   16000,    3800,    3800,  1,      200000 },

        { _OFFSET(enable_dynamic_hc[0]),    1,       1,       1,     0,      1 },
        { _OFFSET(enable_dynamic_hc[1]),    1,       1,       1,     0,      1 },
        { _OFFSET(enable_dynamic_hc[2]),    1,       1,       1,     0,      1 },
        { _OFFSET(enable_dynamic_hc[3]),    0,       0,       0,     0,      1 },
        { _OFFSET(hc_timeout0[SM_RX_ID][0]),       12,      12,      12,    1,      0xff },   /* (20K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_RX_ID][0]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_RX_ID][0]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_RX_ID][0]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout0[SM_RX_ID][1]),       6,       6,       6,     1,      0xff },   /* (40K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_RX_ID][1]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_RX_ID][1]),       120,    120,     120,    1,      0xff },   /* (2K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_RX_ID][1]),       240,    240,     240,    1,      0xff },   /* (1K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout0[SM_RX_ID][2]),       6,       6,       6,     1,      0xff },   /* (40K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_RX_ID][2]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_RX_ID][2]),       120,    120,     120,    1,      0xff },   /* (2K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_RX_ID][2]),       240,    240,     240,    1,      0xff },   /* (1K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout0[SM_RX_ID][3]),       6,       6,       6,     1,      0xff },   /* (40K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_RX_ID][3]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_RX_ID][3]),       120,    120,     120,    1,      0xff },   /* (2K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_RX_ID][3]),       240,    240,     240,    1,      0xff },   /* (1K int/sec assuming no more btr) */

        { _OFFSET(hc_timeout0[SM_TX_ID][0]),       12,      12,      12,    1,      0xff },   /* (20K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_TX_ID][0]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_TX_ID][0]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_TX_ID][0]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout0[SM_TX_ID][1]),       6,       6,       6,     1,      0xff },   /* (40K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_TX_ID][1]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_TX_ID][1]),       120,    120,     120,    1,      0xff },   /* (2K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_TX_ID][1]),       240,    240,     240,    1,      0xff },   /* (1K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout0[SM_TX_ID][2]),        6,       6,       6,    1,      0xff },   /* (40K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_TX_ID][2]),       12,      12,      12,    1,      0xff },   /* (20K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_TX_ID][2]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_TX_ID][2]),       64,      64,      64,    1,      0xff },   /* (3.75K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout0[SM_TX_ID][3]),       6,       6,       6,     1,      0xff },   /* (40K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout1[SM_TX_ID][3]),       48,      48,      48,    1,      0xff },   /* (5K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout2[SM_TX_ID][3]),       120,    120,     120,    1,      0xff },   /* (2K int/sec assuming no more btr) */
        { _OFFSET(hc_timeout3[SM_TX_ID][3]),       240,    240,     240,    1,      0xff },   /* (1K int/sec assuming no more btr) */

        { _OFFSET(hc_threshold0[SM_RX_ID]),        0x2000,  0x2000,  0x2000,1,     0xffffffff },
        { _OFFSET(hc_threshold1[SM_RX_ID]),        0x10000, 0x10000, 0x10000,1,     0xffffffff },
        { _OFFSET(hc_threshold2[SM_RX_ID]),        0x50000, 0x50000, 0x50000,1,     0xffffffff },

        { _OFFSET(hc_threshold0[SM_TX_ID]),        0x2000,  0x2000,  0x2000,1,     0xffffffff },
        { _OFFSET(hc_threshold1[SM_TX_ID]),        0x10000, 0x10000, 0x10000,1,     0xffffffff },
        { _OFFSET(hc_threshold2[SM_TX_ID]),        0x20000, 0x20000, 0x20000,1,     0xffffffff },

        { _OFFSET(l2_dynamic_hc_min_bytes_per_packet),        0,      0,        0,        0,     0xffff },
//        { _OFFSET(l4_hc_scaling_factor),     12,      12,        12,      0,    16 },
        { _OFFSET(l4_hc_ustorm_thresh),     12,     12,       12,     12,     0xffffffff },  /* 128K */
        // l4 params
        { _OFFSET(l4_scq_page_cnt),         2,       2,       2,     2,      127 }, /* 321 BDs are reserved to FW threshold :-( */
        { _OFFSET(l4_rcq_page_cnt),         3,       3,       3,     3,      127 }, /* 398 BDs are reserved to FW threshold :-(  CQ_XOFF_TH = ((65*6) +  8) = ((maximum pending incoming msgs) * (maximum completions) + (maximum ramrods)) */
        { _OFFSET(l4_grq_page_cnt),         2,       2,       2,     2,      127 }, /* 65  BDs are reserved to FW threshold :-( */
        { _OFFSET(l4_tx_chain_page_cnt),    2,       2,       2,     2,      127 },
        { _OFFSET(l4_rx_chain_page_cnt),    2,       2,       2,     2,      127 },
        { _OFFSET(l4_gen_buf_size),         LM_PAGE_SIZE,LM_PAGE_SIZE,LM_PAGE_SIZE,LM_PAGE_SIZE,16*LM_PAGE_SIZE },
        { _OFFSET(l4_history_cqe_cnt),      20,      20,      20,    1,      20   },
        { _OFFSET(l4_ignore_grq_push_enabled), 0,       0,       0,     0,      1   },
        { _OFFSET(l4cli_flags),             0,       0,       0,     0,      1 },
        { _OFFSET(l4cli_ticks_per_second),  1000,    1000,    1000,  500,    10000 },
        { _OFFSET(l4cli_ack_frequency),     2,       2,       2,     1,      255 }, /* default 2 segments */
        { _OFFSET(l4cli_delayed_ack_ticks), 200,     200,     200,   1,      255 }, /* default 200ms */
        { _OFFSET(l4cli_max_retx),          6,       6,       6,     1,      255 },
        { _OFFSET(l4cli_doubt_reachability_retx),3,  3,       3,     1,      255 },
        { _OFFSET(l4cli_sws_prevention_ticks), 1000, 1000,    1000,  200,    0xffffffff }, /* default 1s */
        { _OFFSET(l4cli_dup_ack_threshold), 3,       3,       3,     1,      255 },
        { _OFFSET(l4cli_push_ticks),        100,     100,     100,   1,      0xffffffff }, /* default 100ms */
        { _OFFSET(l4cli_nce_stale_ticks),   0xffffff,0xffffff,0xffffff, 1,   0xffffffff },
        { _OFFSET(l4cli_starting_ip_id),    0,       0,       0,     0,      0xffff },
        { _OFFSET(keep_vlan_tag),           1 ,      1,       1,     0,      1 },
        //congestion managment parameters
        { _OFFSET(cmng_enable),             0,       0,       0,     0,      1},
        { _OFFSET(cmng_rate_shaping_enable),1,       1,       1,     0,      1},
        { _OFFSET(cmng_fairness_enable),    1,       1,       1,     0,      1},
        // safc
        { _OFFSET(cmng_safc_rate_thresh),   3,       3,       3,     0,      10},
        { _OFFSET(cmng_activate_safc),      0,       0,       0,     0,      1},
        // fairness
        { _OFFSET(cmng_fair_port0_rate),    10,      10,      10,    1,      10},
        { _OFFSET(cmng_eth_weight),         8,       8,       8,     0,      10},
        { _OFFSET(cmng_toe_weight),         8,       8,       8,     0,      10},
        { _OFFSET(cmng_rdma_weight),        8,       8,       8,     0,      10},
        { _OFFSET(cmng_iscsi_weight),       8,       8,       8,     0,      10},
        // rate shaping
        { _OFFSET(cmng_eth_rate),           10,      10,      10,    0,      10},
        { _OFFSET(cmng_toe_rate),           10,      10,      10,    0,      10},
        { _OFFSET(cmng_rdma_rate),          2,       2,       2,     0,      10},
        { _OFFSET(cmng_iscsi_rate),         4,       2,       2,     0,      10},
        // Demo will be removed later
        { _OFFSET(cmng_toe_con_number),     20,      20,      20,    0,      1024},
        { _OFFSET(cmng_rdma_con_number),    2,       2,       2,     0,      1024},
        { _OFFSET(cmng_iscsi_con_number),   40,      40,      40,    0,      1024},
        // iscsi
        { _OFFSET(l5sc_max_pending_tasks),      64,          64,      64,    64,     2048},
        // fcoe
        { _OFFSET(max_fcoe_task),           64,      64,      64,    0,     4096},
#if 0
        { _OFFSET(disable_patent_using),        1,       1,       1,     0,      1},
#else
        { _OFFSET(disable_patent_using),        0,       0,       0,     0,      1},
#endif
        { _OFFSET(l4_grq_filling_threshold_divider),    64,       64,       64,     2,      2048},
        { _OFFSET(l4_free_cid_delay_time),  2000,   10000,      10000,  0,  10000},
        { _OFFSET(preemphasis_enable),      0,       0,       0,     0,      1},
        { _OFFSET(preemphasis_rx_0),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_rx_1),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_rx_2),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_rx_3),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_tx_0),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_tx_1),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_tx_2),        0,       0,       0,     0,      0xffff},
        { _OFFSET(preemphasis_tx_3),        0,       0,       0,     0,      0xffff},
        { _OFFSET(disable_pcie_nfr),        0,       0,       0,     0,      1},
        { _OFFSET(debug_cap_flags),  0xffffffff,       0xffffffff,       0xffffffff,     0,      0xffffffff},
        { _OFFSET(try_not_align_page_multiplied_memory),     1,       1,       1,     0,      1},
        { _OFFSET(l4_limit_isles),          0,       0,       0,     0,      1},
        { _OFFSET(l4_max_rcv_wnd_size),     0x100000,0x100000,0x100000, 0,      0x1000000},
        { _OFFSET(ndsb_type),               1,       1,       1,     0,      2},
        { _OFFSET(l4_dominance_threshold),  10,      10,      10,     0,      0xFF},
        { _OFFSET(l4_max_dominance_value),  20,     20,      20,     0,      0xFF},
        { _OFFSET(l4_data_integrity),       0x0,     0x0,     0x0,   0x0,      0x3},
        { _OFFSET(l4_start_port),           5001,  5001,      5001,  0,      0xFFFFFFFF},
        { _OFFSET(l4_num_of_ports),         50,      50,      50,     0,      0xFFFF},
        { _OFFSET(l4_skip_start_bytes),     4,       4,       4,     0,      0xFFFFFFFF},
        { _OFFSET(phy_priority_mode),       PHY_PRIORITY_MODE_HW_DEF, PHY_PRIORITY_MODE_HW_DEF, PHY_PRIORITY_MODE_HW_DEF, PHY_PRIORITY_MODE_HW_DEF, PHY_PRIORITY_MODE_HW_PIN},
        { _OFFSET(grc_timeout_max_ignore),  0,       0,       0,     0,      0xFFFFFFFF},
        { _OFFSET(enable_error_recovery),   0,       0,       0,     0,      1},
        { _OFFSET(validate_sq_complete),    0,       0,       0,     0,      1},
        { _OFFSET(npar_vm_switching_enable),0,       0,       0,     0,      1},
        { _OFFSET(flow_control_reporting_mode),LM_FLOW_CONTROL_REPORTING_MODE_DISABLED,LM_FLOW_CONTROL_REPORTING_MODE_DISABLED,LM_FLOW_CONTROL_REPORTING_MODE_DISABLED,LM_FLOW_CONTROL_REPORTING_MODE_DISABLED,LM_FLOW_CONTROL_REPORTING_MODE_ENABLED},
        { _OFFSET(tpa_desc_cnt_per_chain),  0,       0,       0,     0,      0x10000},
        { _OFFSET(sriov_inc_mac),           0,       0,       0,     0,      64},
        { _OFFSET(e3_cos_modes),            0,       0,       0,     0,      1},
        { _OFFSET(e3_network_cos_mode),     0,       0,       0,     0,      1},
        { _OFFSET(fw_valid_mask),           0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0, 0xFFFFFFFF},
        { _OFFSET(record_sp),               0x0,     0x0,     0x0,   0,      0xf},
        { 0,                                0,       0,       0,     0,      0}
    }; // param_list

    param_entry_t  *param               = NULL;
    size_t          csize               = 0;
    u32_t           flow_control        = 0;
    u8_t            i                   = 0;
    u8_t            port_base_aux_qzone = 0;
    u8_t            base_fw_qzone_id = 0;
    DbgMessage(pdev, INFORMi , "### lm_init_param\n");
    if (!validate)
    {
        /* Initialize the default parameters. */
        param = param_list;
        while(param->offset)
        {
            if(CHIP_REV_IS_FPGA(pdev))
            {
                SET_PARAM_VAL(pdev, param, param->fpga_default);
            }
            else if(CHIP_REV_IS_EMUL(pdev))
            {
                SET_PARAM_VAL(pdev, param, param->emulation_default);
            }
            else
            {
                SET_PARAM_VAL(pdev, param, param->asic_default);
            }
            param++;
        }
        pdev->params.rss_caps = (LM_RSS_CAP_IPV4 | LM_RSS_CAP_IPV6);
        pdev->params.rss_chain_cnt = 1;
        pdev->params.tss_chain_cnt = 1;
        if (IS_PFDEV(pdev))
        {
            pdev->params.sb_cnt = MAX_RSS_CHAINS / pdev->params.vnics_per_port;
            /* base non-default status block idx - 0 in E1. 0, 4, 8 or 12 in E1H */
            if (CHIP_IS_E1x(pdev))
            {
                pdev->params.max_pf_sb_cnt = pdev->params.fw_sb_cnt = HC_SB_MAX_SB_E1X / 2 / pdev->params.vnics_per_port;
                pdev->params.base_fw_ndsb = FUNC_ID(pdev) * pdev->params.fw_sb_cnt;
                if (CHIP_IS_E1(pdev)) {
                    pdev->params.fw_client_cnt = pdev->params.max_pf_fw_client_cnt = ETH_MAX_RX_CLIENTS_E1;
                } else {
                    pdev->params.fw_client_cnt = pdev->params.max_pf_fw_client_cnt = ETH_MAX_RX_CLIENTS_E1H / pdev->params.vnics_per_port;
                }
                pdev->params.base_fw_client_id = VNIC_ID(pdev) * pdev->params.fw_client_cnt;
            }
            else
            {
#ifdef _VBD_
//      pdev->params.sb_cnt = min(LM_IGU_SB_CNT(pdev), MAX_RSS_CHAINS);
        pdev->params.sb_cnt = LM_IGU_SB_CNT(pdev);
#endif
                if (pdev->params.sb_cnt > LM_IGU_SB_CNT(pdev)) {
                    pdev->params.sb_cnt = LM_IGU_SB_CNT(pdev);
                }
// Asymmetric resource division
#ifndef LM_NUM_DSBS
#define LM_NUM_DSBS 1
#endif
                if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
                {
                    pdev->params.base_fw_ndsb = IGU_BASE_NDSB(pdev) - (FUNC_ID(pdev) + 1)* LM_NUM_DSBS;
                    pdev->params.fw_aux_qzone_cnt = (ETH_MAX_RX_CLIENTS_E2 - PXP_REG_HST_ZONE_PERMISSION_TABLE_SIZE) / pdev->params.vnics_per_port / 2;
                    port_base_aux_qzone = PORT_ID(pdev)* ((ETH_MAX_RX_CLIENTS_E2 - PXP_REG_HST_ZONE_PERMISSION_TABLE_SIZE)/PORT_MAX);
                    pdev->params.aux_fw_qzone_id = PXP_REG_HST_ZONE_PERMISSION_TABLE_SIZE + port_base_aux_qzone + VNIC_ID(pdev) * pdev->params.fw_aux_qzone_cnt;
                    pdev->params.base_fw_client_id = pdev->params.base_fw_ndsb + FUNC_ID(pdev) * MAX_NON_RSS_FW_CLIENTS;
                }
                else
                {
                    pdev->params.base_fw_ndsb = IGU_BASE_NDSB(pdev) - (VNIC_ID(pdev) + 1) * LM_NUM_DSBS;
                    pdev->params.fw_aux_qzone_cnt = (ETH_MAX_RX_CLIENTS_E2 - PXP_REG_HST_ZONE_PERMISSION_TABLE_SIZE) / pdev->params.vnics_per_port;
                    pdev->params.aux_fw_qzone_id = PXP_REG_HST_ZONE_PERMISSION_TABLE_SIZE + VNIC_ID(pdev) * pdev->params.fw_aux_qzone_cnt;
                    pdev->params.base_fw_client_id = pdev->params.base_fw_ndsb + VNIC_ID(pdev) * MAX_NON_RSS_FW_CLIENTS;
                }
                pdev->params.fw_sb_cnt = LM_IGU_SB_CNT(pdev);
#ifdef VF_INVOLVED
                pdev->params.fw_sb_cnt = pdev->params.fw_sb_cnt + lm_pf_get_vf_available_igu_blocks(pdev);
                if ((VNICS_PER_PORT(pdev) == 1) && (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_2))
                {
                    pdev->params.fw_client_cnt = ETH_MAX_RX_CLIENTS_E2;
                }
                else
                {
                    pdev->params.fw_client_cnt = pdev->params.fw_sb_cnt + MAX_NON_RSS_FW_CLIENTS;
                }
#else
                pdev->params.fw_client_cnt = pdev->params.fw_sb_cnt + MAX_NON_RSS_FW_CLIENTS;
#endif
                pdev->params.fw_base_qzone_cnt = pdev->params.fw_sb_cnt;
                base_fw_qzone_id = pdev->params.base_fw_ndsb;
                pdev->params.max_pf_sb_cnt = LM_IGU_SB_CNT(pdev);
                pdev->params.max_pf_fw_client_cnt = pdev->params.max_pf_sb_cnt + MAX_NON_RSS_FW_CLIENTS;
            }
            DbgMessage(pdev, WARN, "SB counts(from %d): %d rss, %d max(pf), %d fw ndsbs accessible\n",
                        pdev->params.base_fw_ndsb, pdev->params.sb_cnt, pdev->params.max_pf_sb_cnt, pdev->params.fw_sb_cnt);
            DbgBreakIf(pdev->params.sb_cnt > pdev->params.max_pf_sb_cnt);
            DbgBreakIf(pdev->params.max_pf_sb_cnt > pdev->params.fw_sb_cnt);

//            pdev->params.base_fw_client_id = VNIC_ID(pdev) * pdev->params.fw_client_cnt;
            DbgMessage(pdev, WARN, "FW clients (from %d): %d max(pf), %d fw cliens accessible\n",
                        pdev->params.base_fw_client_id, pdev->params.max_pf_fw_client_cnt, pdev->params.fw_client_cnt);
            if (CHIP_IS_E2E3(pdev)) {
                u8_t qz_idx;
                for (qz_idx = 0; qz_idx < pdev->params.fw_base_qzone_cnt; qz_idx++)
                {
                    pdev->params.fw_qzone_id[qz_idx] = base_fw_qzone_id + qz_idx;

                }
                DbgMessage(pdev, WARN, "%d base FW Q zone IDs from %d\n", pdev->params.fw_base_qzone_cnt, base_fw_qzone_id);
                DbgMessage(pdev, WARN, "%d aux FW Q zone IDs from %d\n", pdev->params.fw_aux_qzone_cnt, pdev->params.aux_fw_qzone_id);
            }
//            pdev->params.base_fw_client_id = VNIC_ID(pdev) * (pdev->params.sb_cnt + MAX_NON_RSS_FW_CLIENTS);
            /* For now, base_fw_qzone_id == base_fw_client_id, but this doesn't have to be the case... */
            /* qzone-id is relevant only for E2 and therefore it is ok that we use a */
            /* Todo - change once E2 client is added. */
//            pdev->params.base_fw_qzone_id = pdev->params.base_fw_client_id + ETH_MAX_RX_CLIENTS_E1H*PORT_ID(pdev);
            /* E2 TODO: read how many sb each pf has...?? */
        } else if (IS_CHANNEL_VFDEV(pdev)) {
            pdev->params.sb_cnt = 16;
        } else {
            pdev->params.sb_cnt = 1;
        }

        pdev->params.max_rss_chains = ((IS_PFDEV(pdev) && IGU_U_NDSB_OFFSET(pdev)) ? min(IGU_U_NDSB_OFFSET(pdev),LM_SB_CNT(pdev)) : LM_SB_CNT(pdev));
        if (pdev->params.max_rss_chains > MAX_RSS_CHAINS)
        {
        pdev->params.max_rss_chains = MAX_RSS_CHAINS;
        }
#ifndef EDIAG
        if(0 == pdev->params.max_rss_chains)
        {
            DbgBreakMsg("Zero isn't a valid value for pdev->params.max_rss_chains  ");
            return LM_STATUS_FAILURE;
        }
#endif
        pdev->params.base_cam_offset = 0;
        /* set the clients cids that will be used by the driver */
        pdev->params.map_client_to_cid[LM_CLI_IDX_NDIS]  = 0;
        pdev->params.map_client_to_cid[LM_CLI_IDX_ISCSI] = i = LM_MAX_RSS_CHAINS(pdev);
        pdev->params.map_client_to_cid[LM_CLI_IDX_OOO]   = ++i;
        pdev->params.map_client_to_cid[LM_CLI_IDX_FCOE]  = ++i;
        pdev->params.map_client_to_cid[LM_CLI_IDX_FWD]   = ++i;
    pdev->params.start_mp_chain = ++i;

//        pdev->params.map_client_to_cid[LM_CLI_IDX_RDMA]  = ++i;
        // FCoE is not supported in E1 and we have only 18 clients in E1
        // so we OOO client gets 'priority' over FCoE
        DbgBreakIf(pdev->params.map_client_to_cid[LM_CLI_IDX_OOO] > pdev->params.map_client_to_cid[LM_CLI_IDX_FCOE]);

        /* L4 RSS */
        pdev->params.l4_rss_chain_cnt = 1;
        pdev->params.l4_tss_chain_cnt = 1;
        /* set l4_rss base chain index to be the first one after l2 */
        pdev->params.l4_rss_base_chain_idx = 0;
        if (CHIP_IS_E1x(pdev))
        {
            pdev->params.l4_base_fw_rss_id = VNIC_ID(pdev) * pdev->params.sb_cnt;
   }
   else
        {
            pdev->params.l4_base_fw_rss_id = VNIC_ID(pdev);
        }
        /* master-pfdev needs to keep resources for its vfs, resource allocation is done first between
         * pfs and then each pf leaves itself 1 sb_cnt for enabling vfs. */
        pdev->params.eth_align_enable = 0;
        lm_init_cam_params(pdev);

        if((CHIP_REV_IS_SLOW(pdev)
#ifdef DUMMY_MAC_FOR_VF
                || IS_VFDEV(pdev)
#endif
                )
                &&
                (!(GET_FLAGS(pdev->hw_info.mf_info.flags,MF_INFO_VALID_MAC))))
        {
            pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0] = 0x00;
            pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1] = 0x50;
            pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2] = 0xc2;
            pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3] = 0x2c;
            pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4] = 0x70 + (IS_PFDEV(pdev) ? 0 : (1 + 64*PATH_ID(pdev) + ABS_VFID(pdev)));
            if (CHIP_IS_E1x(pdev))
            {
                pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5] = 0x9a + 2 * FUNC_ID(pdev);
            }
            else
            {
                pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5] = 0x9a + PATH_ID(pdev)*8 + PORT_ID(pdev)*4 + VNIC_ID(pdev)*2;
            }

            mm_memcpy(pdev->hw_info.iscsi_mac_addr, pdev->hw_info.mac_addr, 6);
            pdev->hw_info.iscsi_mac_addr[5]++;
            mm_memcpy(pdev->hw_info.fcoe_mac_addr, pdev->hw_info.iscsi_mac_addr, 6);
            pdev->hw_info.fcoe_mac_addr[5]++;
            lm_fcoe_set_default_wwns(pdev);
        }
        else
        {
            pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0];
            pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1];
            pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2];
            pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3];
            pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4];
            pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5];
        }
        if(CHIP_REV_IS_EMUL(pdev))
        {
            DbgMessage(pdev, INFORMi, "Emulation is detected.\n");
            pdev->params.test_mode |= TEST_MODE_IGNORE_SHMEM_SIGNATURE;
            pdev->params.test_mode |= TEST_MODE_LOG_REG_ACCESS;
            //pdev->params.test_mode |= TEST_MODE_NO_MCP;
            DbgMessage(pdev, INFORMi , "test mode is 0x%x \n",pdev->params.test_mode);
        }
        else
        {
            DbgMessage(pdev, INFORMi, "ASIC is detected.\n");
        }
        if (!pdev->hw_info.mcp_detected)
        {
            pdev->params.test_mode |= TEST_MODE_NO_MCP;
        }
        flow_control = (pdev->hw_info.link_config[ELINK_INT_PHY] & PORT_FEATURE_FLOW_CONTROL_MASK);

        switch (flow_control)
        {
        case PORT_FEATURE_FLOW_CONTROL_AUTO:
            pdev->params.flow_ctrl_cap = LM_FLOW_CONTROL_AUTO_PAUSE;
        break;
        case PORT_FEATURE_FLOW_CONTROL_TX:
            pdev->params.flow_ctrl_cap = LM_FLOW_CONTROL_TRANSMIT_PAUSE;
        break;
        case PORT_FEATURE_FLOW_CONTROL_RX:
            pdev->params.flow_ctrl_cap = LM_FLOW_CONTROL_RECEIVE_PAUSE;
        break;
        case PORT_FEATURE_FLOW_CONTROL_BOTH:
            pdev->params.flow_ctrl_cap = LM_FLOW_CONTROL_TRANSMIT_PAUSE | LM_FLOW_CONTROL_RECEIVE_PAUSE;
        break;
        case PORT_FEATURE_FLOW_CONTROL_NONE:
            pdev->params.flow_ctrl_cap = LM_FLOW_CONTROL_NONE;
        break;
        default:
            pdev->params.flow_ctrl_cap = LM_FLOW_CONTROL_NONE;
        break;
        }

        /*
         * We don't know (yet...) if the PHY supportes EEE - so we cannot set params
         * to reflect this info.
         */

        /* L2 FW Flow control */
        // cq57766
        // if this static assert fails consider adding the new mode to the if
        // and read the l2_fw_flow_ctrl from the shmem in the new mode also
        ASSERT_STATIC(MAX_MF_MODE == 4);
        if ((pdev->hw_info.mf_info.mf_mode == SINGLE_FUNCTION) ||
            (pdev->hw_info.mf_info.mf_mode == MULTI_FUNCTION_SD) ||
            (CHIP_IS_E1x(pdev)))
        {
            // l2_fw_flow_ctrl is read from the shmem in multi-function mode in E2 and above.
            // In all other cases this parameter is read from the registry.
            // We read this parameter from the registry in E1.5 multi-function since 57711 boot code does not have the struct func_ext_cfg
            pdev->params.l2_fw_flow_ctrl = 0;
        }
        pdev->params.l4_fw_flow_ctrl = 0;
        pdev->params.fw_stats_init_value = TRUE;

        pdev->params.mf_mode = pdev->hw_info.mf_info.mf_mode;
        if (pdev->params.mf_mode == MULTI_FUNCTION_SD) 
        {
            pdev->params.sd_mode = pdev->hw_info.mf_info.sd_mode;
        }
        
    }
    else
    {
        /* Make sure the parameter values are within range. */
        param = param_list;
        while(param->offset)
        {
            if(param->min != 0 || param->max != 0)
            {
                if(PARAM_VAL(pdev, param) < param->min ||
                    PARAM_VAL(pdev, param) > param->max)
                {
                    if(CHIP_REV_IS_FPGA(pdev))
                    {
                        SET_PARAM_VAL(pdev, param, param->fpga_default);
                    }
                    else if(CHIP_REV_IS_EMUL(pdev))
                    {
                        SET_PARAM_VAL(pdev, param, param->emulation_default);
                    }
                    else
                    {
                        SET_PARAM_VAL(pdev, param, param->asic_default);
                    }
                }
            }
            param++;
        }
        /* calculate context_line_size context_waste_size */
        // TODO calculate number of context lines in alocation page.
            csize = max(sizeof(struct eth_context),sizeof(struct toe_context));
            //csize = max(sizeof(struct rdma_context),csize);
            csize = max(sizeof(struct iscsi_context),csize);
            DbgBreakIf(csize>1024);
        /* Check for a valid mac address. */
        if((pdev->params.mac_addr[0] == 0 &&
            pdev->params.mac_addr[1] == 0 &&
            pdev->params.mac_addr[2] == 0 &&
            pdev->params.mac_addr[3] == 0 &&
            pdev->params.mac_addr[4] == 0 &&
            pdev->params.mac_addr[5] == 0) || (pdev->params.mac_addr[0] & 1))
        {
            DbgMessage(pdev, WARNi, "invalid MAC number.\n");
            pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0];
            pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1];
            pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2];
            pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3];
            pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4];
            pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5];
        }
        if (CHIP_IS_E1(pdev))
        {
            if ((pdev->params.l2_fw_flow_ctrl == 1) || (pdev->params.l4_fw_flow_ctrl == 1))
            {
                DbgMessage(pdev, WARNi, "L2 FW Flow control not supported on E1\n");
                pdev->params.l2_fw_flow_ctrl = 0;
                pdev->params.l4_fw_flow_ctrl = 0;
            }
        }
    }

    /* init l2 client conn param with default mtu values */
    for (i = 0; i < ARRSIZE(pdev->params.l2_cli_con_params); i++)
    {
        lm_cli_idx_t lm_cli_idx = LM_CHAIN_IDX_CLI(pdev, i);
        ASSERT_STATIC( ARRSIZE(pdev->params.l2_rx_desc_cnt) == ARRSIZE(pdev->params.mtu));
        if(  lm_cli_idx >= ARRSIZE(pdev->params.l2_rx_desc_cnt))
        {
            // in case lm_cli_idx is above boundries
            // it means that is should not be used (currently expected in MF mode)
            // we skip the iteration
            continue;
        }
        pdev->params.l2_cli_con_params[i].mtu         = pdev->params.mtu[lm_cli_idx];

        if(i < (LM_SB_CNT(pdev) + MAX_NON_RSS_CHAINS))
        {
            pdev->params.l2_cli_con_params[i].num_rx_desc = pdev->params.l2_rx_desc_cnt[lm_cli_idx];
            pdev->params.l2_cli_con_params[i].attributes  = LM_CLIENT_ATTRIBUTES_RX | LM_CLIENT_ATTRIBUTES_TX | LM_CLIENT_ATTRIBUTES_REG_CLI;
        }
        else
        {
            pdev->params.l2_cli_con_params[i].attributes  = LM_CLIENT_ATTRIBUTES_TX;
        }
    }
    return LM_STATUS_SUCCESS;
} /* lm_init_params */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_get_dev_info(
    lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMi , "### lm_get_dev_info\n");

    // initialize "product_version" to 0xffffffff so all platforms will have invalid values (but Windows that will update it later)
    mm_memset( pdev->product_version, 0xff, sizeof(pdev->product_version) );

    lm_status = lm_get_pcicfg_info(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_get_bars_info(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    if (!IS_CHANNEL_VFDEV(pdev)) {
        lm_status = lm_get_chip_id_and_mode(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }
    if (IS_PFDEV(pdev)) {
        // Get function num using me register
        lm_status = lm_get_function_num(pdev);
        if (lm_status != LM_STATUS_SUCCESS) {
            return lm_status;
        }
        // initialize pointers to init arrays (can only do this after we know which chip we are...)
        // We want to do this here to enable IRO access before driver load (ediag/lediag) this is only done
        // for PFs, VFs use PFDEV to access IRO
        if ( lm_set_init_arrs(pdev) != 0 ) {
            DbgMessage(pdev, FATAL, "Unknown chip revision\n");
            return LM_STATUS_UNKNOWN_ADAPTER;
        }
    } else {
            /* For VF, we also get the vf-id here... since we need it from configuration space */
#ifdef VF_INVOLVED
        if (IS_VFDEV(pdev))
        {
            lm_vf_get_vf_id(pdev);
        }
#endif
    }

#ifdef __LINUX
    if (lm_is_function_after_flr(pdev))
    {
        if (IS_PFDEV(pdev)) {
            lm_status = lm_cleanup_after_flr(pdev);
            if(lm_status != LM_STATUS_SUCCESS)
            {
                return lm_status;
            }
        } else {
        /*  8.  Verify that the transaction-pending bit of each of the function in the Device Status Register in the PCIe is cleared. */

#ifdef __LINUX
            u32_t pcie_caps_offset = mm_get_cap_offset(pdev, PCI_CAP_PCIE);
            if (pcie_caps_offset != 0 && pcie_caps_offset != 0xFFFFFFFF) {
                u32_t dev_control_and_status = 0xFFFFFFFF;
                mm_read_pci(pdev, pcie_caps_offset + PCIE_DEV_CTRL, &dev_control_and_status);
                DbgMessage(pdev, FATAL,"Device Control&Status of PCIe caps is %x\n",dev_control_and_status);
                if (dev_control_and_status & (PCIE_DEV_STATUS_PENDING_TRANSACTION << 16)) {
                    DbgBreak();
                }
            }
#else
            DbgMessage(pdev, FATAL, "Function mm_get_cap_offset is not implemented yet\n");
            DbgBreak();
#endif
            lm_fl_reset_clear_inprogress(pdev);
        }
    }
#endif

    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)) {
        pdev->params.max_eth_including_vfs_conns = 1 << (LM_VF_MAX_RVFID_SIZE + LM_VF_CID_WND_SIZE(pdev) + 1);
    } else if (IS_PFDEV(pdev)) {
        pdev->params.max_eth_including_vfs_conns = MAX_VF_ETH_CONS;
        // Registry parameters are read in this stage.
        // As a result pdev->params.is_dcb_ndis_mp_en isn't valid yet.
        if(IS_DCB_SUPPORTED_BY_CHIP(pdev))
        {
            // Add DCB multiple connections
#ifdef _VBD_
            pdev->params.max_eth_including_vfs_conns += 3 * MAX_HW_CHAINS + MAX_NON_RSS_CHAINS;
#else
            pdev->params.max_eth_including_vfs_conns += MAX_ETH_CONS;
#endif
        }
        else
        {
#ifdef _VBD_
            pdev->params.max_eth_including_vfs_conns += MAX_ETH_REG_CHAINS;
#else
            pdev->params.max_eth_including_vfs_conns += MAX_ETH_REG_CONS;
#endif
        }
    }
    else
    {
        pdev->params.max_eth_including_vfs_conns = MAX_RSS_CHAINS;
    }
    if (IS_PFDEV(pdev)) {
        lm_status = lm_get_sriov_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS) {
            return lm_status;
        }
        lm_status = lm_get_nvm_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS) {
            return lm_status;
        }
        lm_status = lm_get_shmem_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS) {
            return lm_status;
        }

    } else if (IS_CHANNEL_VFDEV(pdev)) { //TODO check for basic vf
        pdev->hw_info.mf_info.multi_vnics_mode = 0;
        pdev->hw_info.mf_info.vnics_per_port   = 1;
        pdev->hw_info.mf_info.ext_id            = 0xffff; /* invalid ovlan */ /* TBD - E1H: - what is the right value for Cisco? */
        pdev->hw_info.mcp_detected = FALSE;
        pdev->hw_info.chip_id = CHIP_NUM_5712E;
        pdev->hw_info.max_port_conns =  log2_align(MAX_ETH_CONS);
        pdev->debug_info.ack_en[0] = 1;
    }

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev)) {
        lm_vf_enable_vf(pdev);
    }
#endif
    pdev->ver_num =
        (LM_DRIVER_MAJOR_VER << 24) |
        (LM_DRIVER_MINOR_VER << 16) |
        (LM_DRIVER_FIX_NUM   << 8)  |
         LM_DRIVER_ENG_NUM ;
    mm_build_ver_string(pdev);
    // for debugging only (no other use)
    pdev->ver_num_fw = (BCM_5710_FW_MAJOR_VERSION << 24) |
                       (BCM_5710_FW_MINOR_VERSION << 16) |
                       (BCM_5710_FW_REVISION_VERSION<<8) |
                       (BCM_5710_FW_ENGINEERING_VERSION) ;
    /* get vnic parameters */
    pdev->params.vnics_per_port = pdev->hw_info.mf_info.vnics_per_port;
    pdev->params.ovlan = VALID_OVLAN(OVLAN(pdev)) ? OVLAN(pdev) : 0; // TBD: verify it's the right value (with OfirH)
    pdev->params.multi_vnics_mode = pdev->hw_info.mf_info.multi_vnics_mode;
    pdev->params.path_has_ovlan = pdev->hw_info.mf_info.path_has_ovlan;

    if IS_MULTI_VNIC(pdev)
    {
        lm_cmng_calc_params(pdev);
    }

    if (IS_PFDEV(pdev))
    {
        // clc params
        init_link_params(pdev);
    }

    if (IS_CHANNEL_VFDEV(pdev))
    {
        pdev->hw_info.intr_blk_info.blk_type = INTR_BLK_IGU;
        pdev->hw_info.intr_blk_info.blk_mode = INTR_BLK_MODE_NORM;
        pdev->hw_info.intr_blk_info.access_type = INTR_BLK_ACCESS_IGUMEM;
    }
    else
    {
        lm_status = lm_get_intr_blk_info(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    lm_status = lm_init_params(pdev, 0);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_mcp_cmd_init(pdev);
    if( LM_STATUS_SUCCESS != lm_status )
    {
        // Ediag may want to update the BC version. Don't fail lm_get_dev_info because of lm_mcp_cmd_init
        // in no condition.
        DbgMessage(pdev, FATAL, "lm_get_shmem_info: mcp_cmd_init failed. lm_status=0x%x\n", lm_status);
    }

    if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
    {
        /* We're a single-function port on a mult-function path in a 4-port-mode environment... we need to support 1G */
        if (pdev->params.path_has_ovlan && !pdev->params.multi_vnics_mode)
        {
            DbgMessage(pdev, WARN, "func_id = %d Setting link speed to 1000MBPS\n", ABS_FUNC_ID(pdev));
            SET_MEDIUM_SPEED(pdev->params.req_medium, LM_MEDIUM_SPEED_1000MBPS);
        }
    }

    /* Override the defaults with user configurations. */
    lm_status = mm_get_user_config(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    lm_status = lm_init_params(pdev, 1);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    DbgMessage(pdev, INFORMi , "### lm_get_dev_info exit\n");
    return LM_STATUS_SUCCESS;
} /* lm_get_dev_info */

/*
 *Function Name: lm_get_port_id_from_func_abs
 *
 *Parameters:
 *
 *Description:
 *  returns the port ID according to the func_abs_id
 * E1/E1.5:
 * Port0: 0,2,4,6
 * Port1: 1,3,5,7
 *
 * E2/E32P
 * Port0: 0,1,2,3,4,5,6,7
 *
 * E34P
 * Port0: 0,1,4,5
 * Port1: 2,3,6,7
 *
 *Returns: u8_t port_id
 *
 */
u8_t lm_get_port_id_from_func_abs( const u32_t chip_num,  const lm_chip_port_mode_t lm_chip_port_mode, const u8_t abs_func )
{
    u8_t port_id     = 0xff;
    u8_t modulus_res = 0;

    do
    {
        if( CHIP_IS_E1x_PARAM( chip_num ) )
        {
            port_id = abs_func % PORT_MAX;
            break;
        }

        switch( lm_chip_port_mode )
        {
        case LM_CHIP_PORT_MODE_2:
            {
                // we expect here only E2 or E3
                DbgBreakIf( CHIP_IS_E1x_PARAM( chip_num ) );
                port_id = 0;
            }
            break;

        case LM_CHIP_PORT_MODE_4:
            {
                modulus_res = abs_func % 4;
                switch (modulus_res)
                {
                case 0:
                case 1:
                    port_id = 0;
                    break;
                case 2:
                case 3:
                    port_id = 1;
                    break;
                default:
                    break;
                }
            }
            break;

        default:
            DbgBreakIf(TRUE);
            break;
        } // switch lm_chip_port_mode

    }while(0);

    return port_id;
} /* lm_get_port_id_from_func_abs */

/*
 *Function Name: lm_get_abs_func_vector
 *
 *Parameters:
 *
 *Description:
 *  returns vector of abs_func id's upon parameters
 *
 *Returns: u32_t abs_func_vector
 *
 */
u8_t lm_get_abs_func_vector( const u32_t chip_num,  const lm_chip_port_mode_t chip_port_mode, const u8_t b_multi_vnics_mode, const u8_t path_id )
{
    u8_t abs_func_vector = 0;

    // TODO VF for T7.0

/*
    The following table is mapping between abs func, ports and paths

    |-----------------------------------------------|
    |[#]| CHIP & Mode | PATH(s) | Port(s) | Func(s) |
    |---|-------------|---------|---------|---------|
    |[1]| E1.0 (SF)   |   (0)   |   0,1   |  (0,1)  |
    |   | E1.5  SF    |         |   0,1   |  (0,1)  | (port is same as func)
    |---|-------------|---------|---------|---------|
    |[2]| E1.5 MF     |   (0)   |   0,1   |   0-7   | 0,1,2,3,4,5,6,7 (port is %2 of func)
    |---|-------------|---------|---------|---------|
    |[3]| E2/E32P SF  |   0,1   |   0     |   --->  | (Path 0) 0        | (Path 1) 1
    |---|-------------|---------|---------|---------|
    |[4]| E2/E32P MF  |   0,1   |   0     |   --->  | (Path 0) 0,2,4,6  | (Path 1) 1,3,5,7
    |---|-------------|---------|---------|---------|
    |[5]| E34P SF     |   0,1   |   0,1   |   --->  | (Path 0) 0:port0 2:port1     | (Path 1) 1:port0 3:port1
    |---|-------------|---------|---------|---------|
    |[6]| E34P MF     |   0,1   |   0,1   |   --->  | (Path 0) 0,4:port0 2,6:port1 | (Path 1) 1,5:port0 3,7:port1 (57840)
    |---|-------------|---------|---------|---------|
    |[7]| E34P MF/SF  |   0,1   |   0,1   |   --->  | (Path 0) 0,4:port0 2:port1   | (Path 1) 1,5:port0 3:port1 (57800)
    |---|-------------|---------|---------|---------|
*/
    do
    {
        // [1]
        if( CHIP_IS_E1x_PARAM(chip_num) && !b_multi_vnics_mode )
        {
            SET_BIT( abs_func_vector, 0 );
            SET_BIT( abs_func_vector, 1 );
            break;
        }

        // [2]
        if( CHIP_IS_E1H_PARAM(chip_num) && b_multi_vnics_mode )
        {
            SET_BIT( abs_func_vector, 0 );
            SET_BIT( abs_func_vector, 1 );
            SET_BIT( abs_func_vector, 2 );
            SET_BIT( abs_func_vector, 3 );
            SET_BIT( abs_func_vector, 4 );
            SET_BIT( abs_func_vector, 5 );
            SET_BIT( abs_func_vector, 6 );
            SET_BIT( abs_func_vector, 7 );
            break;
        }

        // If we got here chip should not be ealier than E2
        DbgBreakIf( CHIP_IS_E1x_PARAM(chip_num) );

        // [3] [4] [5] [6]
        switch ( chip_port_mode )
        {
        case LM_CHIP_PORT_MODE_2:
            {
                // we expect here only E2 or E3
                DbgBreakIf( !CHIP_IS_E2_PARAM(chip_num) && !CHIP_IS_E3_PARAM(chip_num) );

                if( b_multi_vnics_mode )
                {
                    // [4]
                    SET_BIT( abs_func_vector, (0 + path_id) );
                    SET_BIT( abs_func_vector, (2 + path_id) );
                    SET_BIT( abs_func_vector, (4 + path_id) );
                    SET_BIT( abs_func_vector, (6 + path_id) );
                    break;
                }
                else
                {
                    // [3]
                    SET_BIT( abs_func_vector, path_id );
                    break;
                }
            } // LM_CHIP_PORT_MODE_2
            break;


        case LM_CHIP_PORT_MODE_4:
            {
                if( b_multi_vnics_mode )
                {
                    // [6]
                    if (chip_num != CHIP_NUM_57800)
                    {
                        SET_BIT( abs_func_vector, (0 + path_id) );
                        SET_BIT( abs_func_vector, (2 + path_id) );
                        SET_BIT( abs_func_vector, (4 + path_id) );
                        SET_BIT( abs_func_vector, (6 + path_id) );

                    }
                    // [7] In 57800 if we are multi function the other port can only be single function
                    else
                    {
                        SET_BIT( abs_func_vector, (0 + path_id) );
                        SET_BIT( abs_func_vector, (2 + path_id) );
                        SET_BIT( abs_func_vector, (4 + path_id) );
                    }
                    break;
                }
                else
                {
                    // [5]
                    if (chip_num != CHIP_NUM_57800)
                    {
                        SET_BIT( abs_func_vector, (0 + path_id) );
                        SET_BIT( abs_func_vector, (2 + path_id) );
                    }
                    // [7] We can't really know what's on the other port, so for this case where we are
                    //     in 57800 single function, we assume multi-function and access all the functions
                    //     so this might be case [5] but we can't know this.
                    else
                    {
                        SET_BIT( abs_func_vector, (0 + path_id) );
                        SET_BIT( abs_func_vector, (2 + path_id) );
                        SET_BIT( abs_func_vector, (4 + path_id) );
                    }
                    break;
                }
            } // LM_CHIP_PORT_MODE_4
            break;

        default:
            {
                DbgBreakIf(TRUE);
                break;
            }
        } // CHIP_PORT_MODE

    }while(0);

    return abs_func_vector;
} /* lm_get_abs_func_vector */

lm_status_t lm_verify_validity_map(lm_device_t *pdev)
{
    u64_t        wait_cnt       = 0 ;
    u64_t        wait_cnt_limit = 200000; // 4 seconds (ASIC)
    u32_t        val            = 0;
    lm_status_t  lm_status      = LM_STATUS_FAILURE ;
    if ( CHK_NULL(pdev) )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }
    wait_cnt_limit*= (u64_t)(pdev->vars.clk_factor) ;
    for(wait_cnt = 0; wait_cnt < wait_cnt_limit; wait_cnt++)
    {
        LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t, validity_map[PORT_ID(pdev)]),&val);
        // check that shared memory is valid.
        if((val & (SHR_MEM_VALIDITY_DEV_INFO | SHR_MEM_VALIDITY_MB)) == (SHR_MEM_VALIDITY_DEV_INFO|SHR_MEM_VALIDITY_MB))
        {
            lm_status = LM_STATUS_SUCCESS ;
            break;
        }
        mm_wait(pdev, 20);
    }
    DbgMessage(pdev, INFORMi, "lm_verify_validity_map: shmem signature %d\n",val);
    return lm_status ;
}


lm_status_t
lm_set_cam_params(struct _lm_device_t * pdev,
                  u32_t mac_requestors_mask,
                  u32_t base_offset_in_cam_table,
                  u32_t cam_size,
                  u32_t mma_size,
                  u32_t mc_size)
{
    lm_status_t lm_status =  LM_STATUS_SUCCESS;
    if (IS_VFDEV(pdev)) {
        return LM_STATUS_FAILURE;
    }
    if (base_offset_in_cam_table != LM_KEEP_CURRENT_CAM_VALUE) {
        pdev->params.base_offset_in_cam_table = (u8_t)base_offset_in_cam_table;
    }
    if (cam_size != LM_KEEP_CURRENT_CAM_VALUE) {
        pdev->params.cam_size = (u8_t)cam_size;
    }
    if (mc_size != LM_KEEP_CURRENT_CAM_VALUE) {
        if (CHIP_IS_E1(pdev)) {
            pdev->params.mc_table_size[LM_CLI_IDX_NDIS]  =(u8_t) mc_size;
        } else {
            pdev->params.mc_table_size[LM_CLI_IDX_FCOE]  = (u8_t)mc_size;
        }
    }

    return lm_status;
} /* lm_set_cam_params */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void lm_cmng_calc_params(lm_device_t* pdev )
{
    u8_t vnic = 0;
    DbgBreakIf(!IS_MULTI_VNIC(pdev));
    for (vnic = 0; vnic < MAX_VNIC_NUM; vnic++)
    {
        if (GET_FLAGS(pdev->hw_info.mf_info.func_mf_cfg , FUNC_MF_CFG_FUNC_HIDE))
        {
            pdev->params.min_bw[vnic] = 0;
            pdev->params.max_bw[vnic] = 0;
        }
        else
        {
            pdev->params.min_bw[vnic] = pdev->hw_info.mf_info.min_bw[vnic];
            pdev->params.max_bw[vnic] = pdev->hw_info.mf_info.max_bw[vnic];
        }
    }
} /* lm_cmng_calc_params */

/**
 * @description
 * Calculates BW according to current linespeed and MF
 * configuration  of the function in Mbps.
 * @param pdev
 * @param link_speed - Port rate in Mbps.
 * @param vnic
 *
 * @return u16
 * Return the max BW of the function in Mbps.
 */
u16_t
lm_get_max_bw(IN const lm_device_t  *pdev,
              IN const u32_t        link_speed,
              IN const u8_t         vnic)
{
    u16_t  max_bw   = 0;

    DbgBreakIf(0 == IS_MULTI_VNIC(pdev));

    //global vnic counter
    if(IS_MF_SD_MODE(pdev) || IS_MF_AFEX_MODE(pdev))
    {
        // SD max BW in 100Mbps
        max_bw = pdev->params.max_bw[vnic]*100;
    }
    else
    {
        // SI max BW in percentage from the link speed.
        DbgBreakIf(FALSE == IS_MF_SI_MODE(pdev));
        max_bw = (link_speed * pdev->params.max_bw[vnic])/100;
    }
    return max_bw;
}

u8_t lm_check_if_pf_assigned_to_vm(struct _lm_device_t *pdev)
{
    u8_t b_assigned_to_vm = FALSE;

    switch (pdev->hw_info.pci_cfg_trust)
    {
        case PCI_CFG_NOT_TESTED_FOR_TRUST:
            break;
        case PCI_CFG_NOT_TRUSTED:
            b_assigned_to_vm = TRUE;
            break;
        case PCI_CFG_TRUSTED:
            b_assigned_to_vm = FALSE;
            break;
    }
    return b_assigned_to_vm;
}

u8_t lm_is_fw_version_valid(struct _lm_device_t *pdev)
{
    u8_t is_fw_valid = FALSE;
    u32_t drv_fw_ver = (BCM_5710_FW_MAJOR_VERSION) |
                       (BCM_5710_FW_MINOR_VERSION << 8) |
                       (BCM_5710_FW_REVISION_VERSION << 16) |
                       (BCM_5710_FW_ENGINEERING_VERSION  << 24) ;
    u32_t real_fw_ver = REG_RD(pdev,0x2c0000); /* Read acitve FW version from 1st DWORD of XSTORM params*/
    u32_t fw_valid_mask;

    fw_valid_mask = SWAP_BYTES32(pdev->params.fw_valid_mask);
    is_fw_valid = (((drv_fw_ver ^ real_fw_ver) & fw_valid_mask) == 0);
    return (is_fw_valid);
}

/*
 * Support for NSCI get OS driver version CQ70040
 */

/*Descripion: Write the client driver version
*              to the shmem2 region
*/
lm_status_t
lm_set_cli_drv_ver_to_shmem(struct _lm_device_t *pdev)
{
    u32_t               drv_ver_offset      = OFFSETOF(shmem2_region_t,func_os_drv_ver);
    u32_t               offset              = 0;
    lm_status_t         lm_status           = LM_STATUS_SUCCESS; //  Status is always SUCCESS now
    u32_t               shmem2_size         = 0;
    u32_t               index               = 0;

    if (IS_VFDEV(pdev))
    {
        return LM_STATUS_SUCCESS;
    }

    ASSERT_STATIC( sizeof(pdev->lm_cli_drv_ver_to_shmem.cli_drv_ver) == sizeof(struct os_drv_ver) );

    offset = drv_ver_offset + (pdev->params.pfunc_mb_id * sizeof(pdev->lm_cli_drv_ver_to_shmem.cli_drv_ver));

    DbgMessage(pdev, WARN,"offset= %d \n", offset);

    if (pdev->hw_info.shmem_base2 != 0)
    {
        LM_SHMEM2_READ (pdev, OFFSETOF(shmem2_region_t,size), &shmem2_size);
        if (shmem2_size > offset)
        {
            for (index = 0; index < ARRSIZE(pdev->lm_cli_drv_ver_to_shmem.cli_drv_ver.versions); index++)
            {
                LM_SHMEM2_WRITE(pdev, offset, pdev->lm_cli_drv_ver_to_shmem.cli_drv_ver.versions[index]);
                offset+= sizeof( pdev->lm_cli_drv_ver_to_shmem.cli_drv_ver.versions[index] );
            }
        }
    }

   return lm_status;
}

u8_t lm_is_mac_locally_administrated(struct _lm_device_t    *pdev, u8_t * mac)
{
    u8_t res = FALSE;
    if (mac != NULL)
    {
        res = (mac[0] != pdev->params.mac_addr[0]) ||
              (mac[1] != pdev->params.mac_addr[1]) ||
              (mac[2] != pdev->params.mac_addr[2]) ||
              (mac[3] != pdev->params.mac_addr[3]) ||
              (mac[4] != pdev->params.mac_addr[4]) ||
              (mac[5] != pdev->params.mac_addr[5]);
    }
    return res;
}
