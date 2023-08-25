/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "lm5706.h"



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u8_t
fw_reset_sync(
    lm_device_t *pdev,
    lm_reason_t reason,
    u32_t msg_data,
    u32_t fw_ack_timeout_us)    /* timeout in microseconds. */
{
    u32_t cnt;
    u32_t val;

    /* Skip handshake for 5709 for emulation */
    if (CHIP_ID(pdev) == CHIP_ID_5709_IKOS)
    {
        return TRUE;
    }

    /* If we timed out, inform the firmware that this is the case. */
    if(pdev->vars.fw_timed_out)
    {
        return TRUE;
    }

    pdev->vars.fw_wr_seq++;
    msg_data |= (pdev->vars.fw_wr_seq & DRV_MSG_SEQ);

    switch(reason)
    {
        case LM_REASON_DRIVER_RESET:
            msg_data |= DRV_MSG_CODE_RESET;
            break;

        case LM_REASON_DRIVER_UNLOAD:
            msg_data |= DRV_MSG_CODE_UNLOAD;
            break;

        case LM_REASON_DRIVER_UNLOAD_POWER_DOWN:
            msg_data |= DRV_MSG_CODE_UNLOAD_LNK_DN;
            break;

        case LM_REASON_DRIVER_SHUTDOWN:
            msg_data |= DRV_MSG_CODE_SHUTDOWN;
            break;

        case LM_REASON_WOL_SUSPEND:
            msg_data |= DRV_MSG_CODE_SUSPEND_WOL;
            break;

        case LM_REASON_NO_WOL_SUSPEND:
            msg_data |= DRV_MSG_CODE_SUSPEND_NO_WOL;
            break;

        case LM_REASON_DIAG:
            msg_data |= DRV_MSG_CODE_DIAG;
            break;

        default:
            DbgBreakMsg("invalid reason code.\n");
            break;
    }

    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.drv_mb),
        msg_data);

    val = 0;

    /* wait for an acknowledgement. */
    for(cnt = 0; cnt < fw_ack_timeout_us/5; cnt++)
    {
        mm_wait(pdev, 5);

        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, drv_fw_mb.fw_mb),
            &val);
        if((val & FW_MSG_ACK) == (msg_data & DRV_MSG_SEQ))
        {
            break;
        }
    }

    if((val & FW_MSG_ACK) != (msg_data & DRV_MSG_SEQ))
    {
        if((msg_data & DRV_MSG_DATA) != DRV_MSG_DATA_WAIT0)
        {
            msg_data &= ~DRV_MSG_CODE;
            msg_data |= DRV_MSG_CODE_FW_TIMEOUT;

            REG_WR_IND(
                pdev,
                pdev->hw_info.shmem_base +
                    OFFSETOF(shmem_region_t, drv_fw_mb.drv_mb),
                msg_data);

            pdev->vars.fw_timed_out = TRUE;
            pdev->fw_timed_out_cnt++;

            DbgMessage(pdev, WARN, "firmware timed out.\n");
        }

        return TRUE;
    }

    return FALSE;
} /* fw_reset_sync */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_context_5706_a0_wa(
    lm_device_t *pdev)
{
    u8_t vcid_to_pcid[96];
    u32_t vcid_addr;
    u32_t pcid_addr;
    u32_t offset;
    u32_t vcid;

    /* In A0 silicon, certain context memory region is not accessible
     * due to address decoding problem.  The bad context memory is identify
     * by its pcid having Bit 3 set.  This table provides a mapping between
     * the virtual context id to the usable physical context id. */
    vcid_to_pcid[0x00] = 0x00; vcid_to_pcid[0x01] = 0x01;
    vcid_to_pcid[0x02] = 0x02; vcid_to_pcid[0x03] = 0x03;
    vcid_to_pcid[0x04] = 0x04; vcid_to_pcid[0x05] = 0x05;
    vcid_to_pcid[0x06] = 0x06; vcid_to_pcid[0x07] = 0x07;
    vcid_to_pcid[0x08] = 0x60; vcid_to_pcid[0x09] = 0x61;   /* bad entries. */
    vcid_to_pcid[0x0a] = 0x62; vcid_to_pcid[0x0b] = 0x63;   /* bad entries. */
    vcid_to_pcid[0x0c] = 0x64; vcid_to_pcid[0x0d] = 0x65;   /* bad entries. */
    vcid_to_pcid[0x0e] = 0x66; vcid_to_pcid[0x0f] = 0x67;   /* bad entries. */
    vcid_to_pcid[0x10] = 0x10; vcid_to_pcid[0x11] = 0x11;
    vcid_to_pcid[0x12] = 0x12; vcid_to_pcid[0x13] = 0x13;
    vcid_to_pcid[0x14] = 0x14; vcid_to_pcid[0x15] = 0x15;
    vcid_to_pcid[0x16] = 0x16; vcid_to_pcid[0x17] = 0x17;
    vcid_to_pcid[0x18] = 0x70; vcid_to_pcid[0x19] = 0x71;   /* bad entries. */
    vcid_to_pcid[0x1a] = 0x72; vcid_to_pcid[0x1b] = 0x73;   /* bad entries. */
    vcid_to_pcid[0x1c] = 0x74; vcid_to_pcid[0x1d] = 0x75;   /* bad entries. */
    vcid_to_pcid[0x1e] = 0x76; vcid_to_pcid[0x1f] = 0x77;   /* bad entries. */
    vcid_to_pcid[0x20] = 0x20; vcid_to_pcid[0x21] = 0x21;
    vcid_to_pcid[0x22] = 0x22; vcid_to_pcid[0x23] = 0x23;
    vcid_to_pcid[0x24] = 0x24; vcid_to_pcid[0x25] = 0x25;
    vcid_to_pcid[0x26] = 0x26; vcid_to_pcid[0x27] = 0x27;
    vcid_to_pcid[0x28] = 0x80; vcid_to_pcid[0x29] = 0x81;   /* bad entries. */
    vcid_to_pcid[0x2a] = 0x82; vcid_to_pcid[0x2b] = 0x83;   /* bad entries. */
    vcid_to_pcid[0x2c] = 0x84; vcid_to_pcid[0x2d] = 0x85;   /* bad entries. */
    vcid_to_pcid[0x2e] = 0x86; vcid_to_pcid[0x2f] = 0x87;   /* bad entries. */
    vcid_to_pcid[0x30] = 0x30; vcid_to_pcid[0x31] = 0x31;
    vcid_to_pcid[0x32] = 0x32; vcid_to_pcid[0x33] = 0x33;
    vcid_to_pcid[0x34] = 0x34; vcid_to_pcid[0x35] = 0x35;
    vcid_to_pcid[0x36] = 0x36; vcid_to_pcid[0x37] = 0x37;
    vcid_to_pcid[0x38] = 0x90; vcid_to_pcid[0x39] = 0x91;   /* bad entries. */
    vcid_to_pcid[0x3a] = 0x92; vcid_to_pcid[0x3b] = 0x93;   /* bad entries. */
    vcid_to_pcid[0x3c] = 0x94; vcid_to_pcid[0x3d] = 0x95;   /* bad entries. */
    vcid_to_pcid[0x3e] = 0x96; vcid_to_pcid[0x3f] = 0x97;   /* bad entries. */
    vcid_to_pcid[0x40] = 0x40; vcid_to_pcid[0x41] = 0x41;
    vcid_to_pcid[0x42] = 0x42; vcid_to_pcid[0x43] = 0x43;
    vcid_to_pcid[0x44] = 0x44; vcid_to_pcid[0x45] = 0x45;
    vcid_to_pcid[0x46] = 0x46; vcid_to_pcid[0x47] = 0x47;
    vcid_to_pcid[0x48] = 0xa0; vcid_to_pcid[0x49] = 0xa1;   /* bad entries. */
    vcid_to_pcid[0x4a] = 0xa2; vcid_to_pcid[0x4b] = 0xa3;   /* bad entries. */
    vcid_to_pcid[0x4c] = 0xa4; vcid_to_pcid[0x4d] = 0xa5;   /* bad entries. */
    vcid_to_pcid[0x4e] = 0xa6; vcid_to_pcid[0x4f] = 0xa7;   /* bad entries. */
    vcid_to_pcid[0x50] = 0x50; vcid_to_pcid[0x51] = 0x51;
    vcid_to_pcid[0x52] = 0x52; vcid_to_pcid[0x53] = 0x53;
    vcid_to_pcid[0x54] = 0x54; vcid_to_pcid[0x55] = 0x55;
    vcid_to_pcid[0x56] = 0x56; vcid_to_pcid[0x57] = 0x57;
    vcid_to_pcid[0x58] = 0xb0; vcid_to_pcid[0x59] = 0xb1;   /* bad entries. */
    vcid_to_pcid[0x5a] = 0xb2; vcid_to_pcid[0x5b] = 0xb3;   /* bad entries. */
    vcid_to_pcid[0x5c] = 0xb4; vcid_to_pcid[0x5d] = 0xb5;   /* bad entries. */
    vcid_to_pcid[0x5e] = 0xb6; vcid_to_pcid[0x5f] = 0xb7;   /* bad entries. */

    vcid = sizeof(vcid_to_pcid);
    while(vcid)
    {
        vcid--;

        vcid_addr = GET_PCID_ADDR(vcid);
        pcid_addr = GET_PCID_ADDR(vcid_to_pcid[vcid]);

        /* There maybe some residuals in the context that may cause
         * receive problem later.  The problem intermittently occurs
         * when we are resetting the chip while there are incoming
         * traffic and some other firmware is running.  To prevent this
         * problem from occuring we need to zero out context first
         * before initializing the virtual to physical mapping.  We
         * arbitrarily use a virtual context address 0x00 to map to a
         * physical context one at a time then zero them out.
         *
         * First map the physical context to virtual context 0 then
         * zero out the context. */
        REG_WR(pdev, context.ctx_virt_addr, 0x00);
        REG_WR(pdev, context.ctx_page_tbl, pcid_addr);

        /* Zero out the context. */
        for(offset = 0; offset < PHY_CTX_SIZE; offset += 4)
        {
            CTX_WR(pdev, 0x00, offset, 0);
        }

        /* Now initalize the correct mapping in which the virtual
         * context to the correspondinding physical context. */
        REG_WR(pdev, context.ctx_virt_addr, vcid_addr);
        REG_WR(pdev, context.ctx_page_tbl, pcid_addr);
    }
} /* init_context_5706_a0_wa */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_context_5706(
    lm_device_t *pdev)
{
    u32_t vcid_addr;
    u32_t offset;

    vcid_addr = GET_CID_ADDR(96);   /* This corresponds to 48 context. */

    while(vcid_addr)
    {
        vcid_addr -= PHY_CTX_SIZE;

        /* There maybe some residuals in the context that may cause
         * receive problem later.  The problem intermittently occurs
         * when we are resetting the chip while there are incoming
         * traffic and some other firmware is running.  To prevent this
         * problem from occuring we need to zero out context first
         * before initializing the virtual to physical mapping.  We
         * arbitrarily use a virtual context address 0x00 to map to a
         * physical context one at a time then zero them out.
         *
         * First map the physical context to virtual context 0 then
         * zero out the context. */
        REG_WR(pdev, context.ctx_virt_addr, 0x00);
        REG_WR(pdev, context.ctx_page_tbl, vcid_addr);

        /* Zero out the context. */
        for(offset = 0; offset < PHY_CTX_SIZE; offset += 4)
        {
            CTX_WR(pdev, 0x00, offset, 0);
        }

        /* Now initalize the correct mapping in which the virtual
         * context to the correspondinding physical context. */
        REG_WR(pdev, context.ctx_virt_addr, vcid_addr);
        REG_WR(pdev, context.ctx_page_tbl, vcid_addr);
    }
} /* init_context_5706 */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_context_5709(
    lm_device_t *pdev)
{
    lm_address_t mem_phy;
    u8_t *mem_virt;
    u32_t mem_size;
    u32_t page_idx;
    u32_t idx;
    u32_t cnt;
    u32_t val;

    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);

    val = 0x3001;
    val |= (LM_PAGE_BITS - 8) << 16;
    REG_WR(pdev, context.ctx_command, val);

    page_idx = 0;

    for(idx = 0; idx < NUM_CTX_MBLKS; idx++)
    {
        mem_virt = pdev->vars.ctx_mem[idx].start;
        mem_phy = pdev->vars.ctx_mem[idx].start_phy;
        mem_size = pdev->vars.ctx_mem[idx].size;

        DbgBreakIf(mem_phy.as_u32.low & LM_PAGE_MASK);
        DbgBreakIf(mem_size & LM_PAGE_MASK);

        while(mem_size)
        {
            for(cnt = 0; cnt < LM_PAGE_SIZE; cnt += 4)
            {
                ((u32_t *) mem_virt)[cnt/4] = 0;
            }

            REG_WR(
                pdev,
                context.ctx_host_page_tbl_data0,
                mem_phy.as_u32.low | CTX_HOST_PAGE_TBL_DATA0_VALID);
            REG_WR(
                pdev,
                context.ctx_host_page_tbl_data1,
                mem_phy.as_u32.high);
            REG_WR(
                pdev,
                context.ctx_host_page_tbl_ctrl,
                page_idx | CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ);

            for(cnt = 0; cnt < 100; cnt++)
            {
                REG_RD(pdev, context.ctx_host_page_tbl_ctrl, &val);

                if(!(val & CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ))
                {
                    break;
                }

                mm_wait(pdev, 5);
            }

            DbgBreakIf(val & CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ);

            mem_virt += LM_PAGE_SIZE;
            LM_INC64(&mem_phy, LM_PAGE_SIZE);
            mem_size -= LM_PAGE_SIZE;

            page_idx++;
        }
    }
} /* init_context_5709 */



/*******************************************************************************
 * Description:
 *    This workaround must be applied right after a CORE clock reset
 *    and before enable other blocks which may try to allocate mbufs.
 *
 * Return:
 ******************************************************************************/
STATIC void
alloc_bad_rbuf_5706_a0_wa(
    lm_device_t *pdev)
{
    u16_t good_mbuf[512];
    u32_t good_mbuf_cnt;
    u32_t val;

    REG_WR(
        pdev,
        misc.misc_enable_set_bits,
        MISC_ENABLE_SET_BITS_RX_MBUF_ENABLE);

    good_mbuf_cnt = 0;

    /* Allocate a bunch of mbufs and save the good ones in an array. */
    REG_RD_IND(pdev, OFFSETOF(reg_space_t, rbuf.rbuf_status1), &val);
    while(val & RBUF_STATUS1_FREE_COUNT)
    {
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_command),
            RBUF_COMMAND_ALLOC_REQ_TE);

        REG_RD_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_fw_buf_alloc),
            &val);
        val &= RBUF_FW_BUF_ALLOC_VALUE;

        /* The addresses with Bit 9 set are bad memory blocks. */
        if(!(val & (1 << 9)))
        {
            DbgBreakIf(good_mbuf_cnt >= sizeof(good_mbuf)/sizeof(u16_t));

            good_mbuf[good_mbuf_cnt] = (u16_t) val;
            good_mbuf_cnt++;
        }

        REG_RD_IND(pdev, OFFSETOF(reg_space_t, rbuf.rbuf_status1), &val);
    }

    /* Free the good ones back to the mbuf pool thus discardining
     * all the bad ones. */
    while(good_mbuf_cnt)
    {
        good_mbuf_cnt--;

        val = good_mbuf[good_mbuf_cnt];
        val = (val << 9) | val | 1;

        REG_WR_IND(pdev, OFFSETOF(reg_space_t, rbuf.rbuf_fw_buf_free), val);
    }
} /* alloc_bad_rbuf_5706_a0_wa */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_chip_reset(
    lm_device_t *pdev,
    lm_reason_t reason)
{
    u32_t val;
    u32_t idx;

    DbgMessage(pdev, VERBOSE, "+++ lm_chip_reset\n");
    pdev->chip_reset_cnt++;

    /* acquiesce the bus before a reset. */
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        REG_WR(
            pdev,
            misc.misc_enable_clr_bits,
            MISC_ENABLE_CLR_BITS_TX_DMA_ENABLE |
                MISC_ENABLE_CLR_BITS_DMA_ENGINE_ENABLE |
                MISC_ENABLE_CLR_BITS_RX_DMA_ENABLE);
        mm_wait(pdev, 5);
    }
    else
    {
        if(CHIP_ID(pdev) == CHIP_ID_5709_A0)
        {
            /* Disable bus_master. */
            REG_RD_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_command),
                &val);
            val &= ~PCICFG_COMMAND_BUS_MASTER;
            REG_WR_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_command),
                val);
        }
        else
        {
            /* Disable DMA activities. */
            REG_RD(pdev, misc.misc_new_core_ctl, &val);
            val &= ~(1 << 16);
            REG_WR(pdev, misc.misc_new_core_ctl, val);
        }

        /* wait until there is no pending transaction. */
        for(idx = 0; idx < 1000; idx++)
        {
            REG_RD_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_device_control),
                &val);
            if((val & (PCICFG_DEVICE_STATUS_NO_PEND << 16)) == 0)
            {
                break;
            }

            mm_wait(pdev, 5);
        }
    }

    /* Enable or disable remote phy. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_cap_mb.fw_cap_mb),
        &val);

    if((val & CAPABILITY_SIGNATURE_MASK) == FW_CAP_SIGNATURE)
    {
        val = DRV_ACK_CAP_SIGNATURE;

        if(pdev->params.enable_remote_phy)
        {
            if (LM_REASON_DIAG != reason)
            {
                val |= FW_CAP_REMOTE_PHY_CAPABLE;
            }
            else
            {
                val &= ~FW_CAP_REMOTE_PHY_CAPABLE;
            }
        }

        REG_WR_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, drv_fw_cap_mb.drv_ack_cap_mb),
            val);
    }

    /* Wait for the firmware to tell us it is ok to issue a reason. */
    (void) fw_reset_sync(pdev, reason, DRV_MSG_DATA_WAIT0, FW_ACK_TIME_OUT_MS*1000);

    /* Deposit a driver reset signature so the firmware knows
     * that this is a soft reset. */
    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.drv_reset_signature),
        DRV_RESET_SIGNATURE);

    /* Force the driver to wait for the acknowledgement from
     * the firmware. */
    pdev->vars.fw_timed_out = FALSE;

    /* Do a dummy read to force the chip to complete all current
     * transaction before we issue a reset.  This is a workaround
     * for A0.  If there is any pending transactions when a reset
     * occur, the chip will lock up.  There must be one last read
     * before a core clock reset. */
    REG_RD(pdev, misc.misc_id, &val);

    /* Chip reset. */
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        REG_WR(
            pdev,
            pci_config.pcicfg_misc_config,
            PCICFG_MISC_CONFIG_CORE_RST_REQ |
                PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
                PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP);

        /* Wait for the firmware to configure for PLL bypass.  This is a
         * 5706 A0 workaround.  Without the wait the system will lock up
         * on the first register access in PCI-X mode and may intermittently
         * do the same in PCI mode. */
        if(CHIP_ID(pdev) == CHIP_ID_5706_A0 || CHIP_ID(pdev) == CHIP_ID_5706_A1)
        {
            /* 15ms is how long for the first stage of bootcode to load
             * and set up the PLL bypass. */
            for(idx = 0; idx < 1000; idx++)
            {
                mm_wait(pdev, 15);
            }
        }

        /* Reset takes at approximate 3ms on the FPGA which is 100 times
         * slower than the real chip.  IKOS is 10 times slower than the FPGA. */
        for(idx = 0; idx < 5000; idx++)
        {
            REG_RD(pdev, pci_config.pcicfg_misc_config, &val);

            mm_wait(pdev, 10);

            if((val & (
                PCICFG_MISC_CONFIG_CORE_RST_REQ |
                PCICFG_MISC_CONFIG_CORE_RST_BSY)) == 0)
            {
                break;
            }
        }

        DbgBreakIf(val & (
            PCICFG_MISC_CONFIG_CORE_RST_REQ |
            PCICFG_MISC_CONFIG_CORE_RST_BSY));
    }
    else
    {
        REG_WR(pdev, misc.misc_command, MISC_COMMAND_SW_RESET);

        /* Flush the previous write and wait at least 500 nsec */
        REG_RD( pdev, misc.misc_command, &val);
        mm_wait(pdev, 1);

        /* Reset takes at approximate 3ms on the FPGA which is 100 times
         * slower than the real chip.  IKOS is 10 times slower than the FPGA. */
        for(idx = 0; idx < 5000; idx++)
        {
            REG_RD(pdev, misc.misc_command, &val);

            mm_wait(pdev, 10);

            if((val & MISC_COMMAND_SW_RESET) == 0)
            {
                break;
            }
        }

        DbgBreakIf(val & MISC_COMMAND_SW_RESET);

        REG_WR(
            pdev,
            pci_config.pcicfg_misc_config,
            PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
                PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP);

        if(CHIP_ID(pdev) == CHIP_ID_5709_A0)
        {
            REG_RD_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_command),
                &val);
            val |= PCICFG_COMMAND_BUS_MASTER;
            REG_WR_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_command),
                val);

            /* cq#28345. */
            REG_RD(pdev, tsch.tsch_ctx_access_cfg, &val);
            val &= ~TSCH_CTX_ACCESS_CFG_L5_TCMD_PREFETCH_SIZE;
            REG_WR(pdev, tsch.tsch_ctx_access_cfg, val);
        }
        else
        {
            if((reason == LM_REASON_DRIVER_RESET) || (reason == LM_REASON_DIAG))
            {
                /* Enable DMA activities. */
                REG_RD(pdev, misc.misc_new_core_ctl, &val);
                val |= (1 << 16);
                REG_WR(pdev, misc.misc_new_core_ctl, val);
            }
        }

        if(CHIP_ID(pdev) == CHIP_ID_5709_A0 ||
            CHIP_ID(pdev) == CHIP_ID_5709_B0 ||
            CHIP_ID(pdev) == CHIP_ID_5709_B1 ||
            CHIP_ID(pdev) == CHIP_ID_5709_B2 ||
            CHIP_ID(pdev) == CHIP_ID_5709_A1)
        {
            REG_RD(pdev, mq.mq_config, &val);
            REG_WR(pdev, mq.mq_config, val | MQ_CONFIG_HALT_DIS);
        }
    }

    DbgMessage1(pdev, INFORM, "Reset done, idx = %d\n", idx);

    /* Wait for the firmware to finish its initialization. */
    (void) fw_reset_sync(pdev, reason, DRV_MSG_DATA_WAIT1, FW_ACK_TIME_OUT_MS*1000);

    /* Make sure byte swapping is properly configured. */
    REG_RD(pdev, pci.pci_swap_diag0, &val);

    DbgBreakIf(val != 0x01020304);

    /* The emac block will lock up if the power_down_mode is enabled.
     *
     * This is now done by the bootcode.
     *
     * lm_mread(pdev, PHY_CTRL_REG, &val);
     * if(val & PHY_CTRL_LOWER_POWER_MODE)
     * {
     *    val &= ~PHY_CTRL_LOWER_POWER_MODE;
     *    lm_mwrite(pdev, PHY_CTRL_REG, val);
     * } */

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        /* make sure the MSI-X setting is preserved */
        REG_WR(pdev,
               pci.pci_grc_window_addr,
               (pdev->hw_info.shmem_base & ~0x7fff) |
                PCI_GRC_WINDOW_ADDR_SEP_WIN);

        REG_WR(pdev,
               pci.pci_grc_window1_addr,
               (pdev->hw_info.shmem_base & ~0x7fff) + 0x6000 /*0x16e000 */);

        REG_WR(pdev,
               pci.pci_grc_window2_addr,
               MSIX_TABLE_ADDR /*MSIX vector addr */);
        REG_WR(pdev,
               pci.pci_grc_window3_addr,
               MSIX_PBA_ADDR /*MSIX PBA addr */);
        REG_WR(pdev, pci.pci_msix_tbl_off_bir, PCI_GRC_WINDOW2_BASE);
        REG_WR(pdev, pci.pci_msix_pba_off_bit, PCI_GRC_WINDOW3_BASE);
        if(pdev->params.ena_large_grc_timeout)
        {
            /* this workaround cause IBM minnow to reboot randomly */
            /* set large GRC timeout in MSIX mode */
            REG_RD(pdev, misc.misc_eco_hw_ctl, &val);
            val |= MISC_ECO_HW_CTL_LARGE_GRC_TMOUT_EN;
            REG_WR(pdev, misc.misc_eco_hw_ctl, val);
        }
        else
        {
            REG_RD(pdev, misc.misc_eco_hw_ctl, &val);
            val &= ~MISC_ECO_HW_CTL_LARGE_GRC_TMOUT_EN;
            REG_WR(pdev, misc.misc_eco_hw_ctl, val);
        }
    }
    else
    {
        /* Default 32k window. */
        REG_WR(pdev, pci.pci_grc_window_addr, pdev->hw_info.shmem_base & ~0x7fff);
    }

    /* 5706A0 workaround. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A0)
    {
        /* Adjust the voltage regular to two steps lower.  The default
         * of this register is 0x0000000e. */
        REG_WR(pdev, misc.misc_vreg_control, 0x000000fa);

        /* Remove bad rbuf memory from the free pool. */
        alloc_bad_rbuf_5706_a0_wa(pdev);
    }

    REG_WR(
        pdev,
        timer.timer_sw_tmr_reload_value1,
        pdev->params.tmr_reload_value1);

    (void) lm_set_mac_addr(pdev, 0x0, pdev->params.mac_addr);

    val = pdev->params.mac_addr[0] +
        (pdev->params.mac_addr[1] << 8) +
        (pdev->params.mac_addr[2] << 16) +
        pdev->params.mac_addr[3] +
        (pdev->params.mac_addr[4] << 8) +
        (pdev->params.mac_addr[5] << 16);
    REG_WR(pdev, emac.emac_backoff_seed, val);

    (void) lm_set_rx_mask(
        pdev,
        RX_FILTER_USER_IDX0,
        pdev->rx_info.mask[RX_FILTER_USER_IDX0]);

    /* The firmware relies on the driver to issue a periodic pulse to
     * determine when to go enter an OS absent mode.  During debugging
     * we may not want the firmware to go into this mode. */
    if(pdev->params.test_mode & TEST_MODE_DRIVER_PULSE_ALWAYS_ALIVE)
    {
        pdev->vars.drv_pulse_wr_seq++;

        val = pdev->vars.drv_pulse_wr_seq | DRV_PULSE_ALWAYS_ALIVE;

        REG_WR_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, drv_fw_mb.drv_pulse_mb),
            val);
    }
} /* lm_chip_reset */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_setup_bd_chain_ring(
    u8_t *mem_virt,
    lm_address_t mem_phy,
    u32_t page_cnt)
{
    lm_address_t start_mem_phy;
    u8_t *start_mem_virt;
    tx_bd_next_t *next_ptr;
    u32_t idx;

    DbgBreakIf(
        ((u32_t) PTR_SUB(mem_virt, 0) & LM_PAGE_MASK) !=
            (mem_phy.as_u32.low & LM_PAGE_MASK));

    start_mem_phy = mem_phy;
    start_mem_virt = mem_virt;

    for(idx = 0; idx < page_cnt-1; idx++)
    {
        /* Increment mem_phy to the next page. */
        LM_INC64(&mem_phy, LM_PAGE_SIZE);

        next_ptr = &((tx_bd_next_t *) mem_virt)[MAX_BD_PER_PAGE];

        /* Initialize the physical address of the next bd chain. */
        next_ptr->tx_bd_next_paddr_hi = mem_phy.as_u32.high;
        next_ptr->tx_bd_next_paddr_lo = mem_phy.as_u32.low;

        /* Initialize the virtual address of the next bd chain. */
        *((u8_t **) next_ptr->tx_bd_next_reserved) = mem_virt + LM_PAGE_SIZE;

        /* Move to the next bd chain. */
        mem_virt += LM_PAGE_SIZE;
    }

    next_ptr = &((tx_bd_next_t *) mem_virt)[MAX_BD_PER_PAGE];

    next_ptr->tx_bd_next_paddr_hi = start_mem_phy.as_u32.high;
    next_ptr->tx_bd_next_paddr_lo = start_mem_phy.as_u32.low;
    *((u8_t **) next_ptr->tx_bd_next_reserved) = start_mem_virt;
} /* lm_setup_bd_chain_ring */



#ifndef EXCLUDE_KQE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
setup_page_table(
    void *page_table,
    u32_t page_cnt,
    lm_address_t page_base_phy)
{
    u32_t *page_entry;

    page_entry = (u32_t *) page_table;
    while(page_cnt)
    {
        /* Each entry needs to be in big endian format. */
        *page_entry = page_base_phy.as_u32.high;
        page_entry++;
        *page_entry = page_base_phy.as_u32.low;
        page_entry++;

        LM_INC64(&page_base_phy, LM_PAGE_SIZE);

        page_cnt--;
    }
} /* setup_page_table */
#endif


#if INCLUDE_OFLD_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
l4_reset_setup(
    lm_device_t *pdev)
{
    u32_t val;

    lm_setup_bd_chain_ring(
        (u8_t *) pdev->ofld.gen_chain.bd_chain_virt,
        pdev->ofld.gen_chain.bd_chain_phy,
        pdev->params.gen_bd_page_cnt);

    pdev->ofld.gen_chain.prod_idx = 0;
    pdev->ofld.gen_chain.prod_bseq = 0;
    pdev->ofld.gen_chain.prod_bd = pdev->ofld.gen_chain.bd_chain_virt;

    /* Don't count the last bd of a BD page.  A full BD chain must
     * have at least one empty entry. */
    pdev->ofld.gen_chain.bd_left =  pdev->params.gen_bd_page_cnt *
        MAX_BD_PER_PAGE - 1;

    DbgMessage2(pdev, INFORMrs, "gen_chain %p, bd_left %d\n",
        pdev->ofld.gen_chain.bd_chain_virt,
        pdev->ofld.gen_chain.bd_left);

    /* Initialize the type, size, bd_pre_read. */
    val = L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE << 24;
    val |= (((sizeof(l2_bd_chain_context_t) + 0x1f) & ~0x1f) / 0x20) << 16;
    val |= 0x2 << 8;
    CTX_WR(
        pdev,
        pdev->ofld.gen_chain.cid_addr,
        WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_ctx_type),
        val);

    val = pdev->ofld.gen_chain.bd_chain_phy.as_u32.high;
    CTX_WR(
        pdev,
        pdev->ofld.gen_chain.cid_addr,
        WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_nx_bdhaddr_hi),
        val);

    val = pdev->ofld.gen_chain.bd_chain_phy.as_u32.low;
    CTX_WR(
        pdev,
        pdev->ofld.gen_chain.cid_addr,
        WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_nx_bdhaddr_lo),
        val);

    /* Set up the hcopy chain. */
    if(pdev->params.hcopy_desc_cnt)
    {
        lm_setup_bd_chain_ring(
            (u8_t *) pdev->ofld.hcopy_chain.bd_chain_virt,
            pdev->ofld.hcopy_chain.bd_chain_phy,
            pdev->params.hcopy_bd_page_cnt);

        pdev->ofld.hcopy_chain.prod_bd =
            pdev->ofld.hcopy_chain.bd_chain_virt;
        pdev->ofld.hcopy_chain.prod_idx = 0;
        pdev->ofld.hcopy_chain.con_idx = 0;
        pdev->ofld.hcopy_chain.prod_bseq = 0;

        /* Don't count the last bd of a BD page.  A full BD chain must
         * have at least one empty entry. */
        pdev->ofld.hcopy_chain.bd_left = pdev->params.hcopy_bd_page_cnt *
            MAX_BD_PER_PAGE - 1;

        val = L4CTX_TYPE_TYPE_L2 << 24;
        val |= (((sizeof(l4_context_t) + 0x1f) & ~0x1f) / 0x20) << 16;
        CTX_WR(
            pdev,
            pdev->ofld.hcopy_chain.cid_addr,
            WORD_ALIGNED_OFFSETOF(l4_context_t, l4ctx_ctx_type),
            val);

        val = (CCELL_CMD_TYPE_TYPE_L2 | ((LM_PAGE_BITS-8) << 4)) << 24;
        val |= 8 << 16;
        CTX_WR(
            pdev,
            pdev->ofld.hcopy_chain.cid_addr,
            WORD_ALIGNED_OFFSETOF(l4_context_t, l4ctx_cmd),
            val);

        val = pdev->ofld.hcopy_chain.bd_chain_phy.as_u32.high;
        CTX_WR(
            pdev,
            pdev->ofld.hcopy_chain.cid_addr,
            WORD_ALIGNED_OFFSETOF(l4_context_t, l4ctx_cmd) +
            WORD_ALIGNED_OFFSETOF(tcp_context_cmd_cell_te_t,
                ccell_tbdr_bhaddr.hi),
            val);

        val = pdev->ofld.hcopy_chain.bd_chain_phy.as_u32.low;
        CTX_WR(
            pdev,
            pdev->ofld.hcopy_chain.cid_addr,
            WORD_ALIGNED_OFFSETOF(l4_context_t, l4ctx_cmd) +
            WORD_ALIGNED_OFFSETOF(tcp_context_cmd_cell_te_t,
                ccell_tbdr_bhaddr.lo),
            val);
    }

    /* Setup statistics mapping. */
    REG_WR(
        pdev,
        hc.hc_stat_gen_sel_0,
        HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT0_TE |             /* 0 - inseg */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT1_TE << 8) |  /* 1 - inerr */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT2_TE << 16) | /* 2 - inrecv */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT3_TE << 24)); /* 3 - inhdrerr */

    REG_WR(
        pdev,
        hc.hc_stat_gen_sel_1,
        HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT4_TE |             /* 4 - indiscard */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT5_TE << 8) |  /* 5 - indeliver */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT0_TE << 16) | /* 6 - outseg */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT1_TE << 24)); /* 7 - retrans */

    REG_WR(
        pdev,
        hc.hc_stat_gen_sel_2,
        HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT2_TE |             /* 8 - outreset */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT3_TE << 8) |  /* 9 - outreq */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT4_TE << 16) | /* 10 - outdiscrd */
            (HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT5_TE << 24)); /* 11 - outnorte */

    /* set enable_iscsi_fast_response. */
    REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(enable_fast_iscsi_response),
            pdev->params.enable_fir);
} /* l4_reset_setup */
#endif



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_l2txq(
    lm_device_t *pdev)
{
    lm_tx_chain_t *txq;
    u32_t bd_page_cnt;
    u32_t offset;
    u32_t idx;
    u32_t val;

    for(idx = 0; idx < sizeof(lm_tx_stats_t)/sizeof(u32_t); idx++)
    {
        ((u32_t *) &pdev->tx_info.stats)[idx] = 0;
    }

    for(idx = 0; idx < pdev->tx_info.num_txq; idx++)
    {
        txq = &pdev->tx_info.chain[idx];

        bd_page_cnt = pdev->params.l2_tx_bd_page_cnt[txq->idx];

        txq->prod_idx = 0;
        txq->con_idx = 0;
        txq->prod_bseq = 0;
        txq->prod_bd = txq->bd_chain_virt;
        txq->bd_left = bd_page_cnt * MAX_BD_PER_PAGE - 1;

        if(bd_page_cnt == 0)
        {
            continue;
        }

        lm_setup_bd_chain_ring(
            (u8_t *) txq->bd_chain_virt,
            txq->bd_chain_phy,
            bd_page_cnt);

#ifndef L2_ONLY
        val = (L4CTX_TYPE_TYPE_L2 << 24) |
              (((sizeof(l4_context_t) + 0x1f) & ~0x1f) / 0x20) << 16;
#else
        // This is equivalent as above, but some constants/structures are not
        // defined for Solaris
        val = (0x10 << 24) |
              (((80 * sizeof(u32_t) + 0x1f) & ~0x1f) / 0x20) << 16;
#endif

        if (CHIP_NUM(pdev) == CHIP_NUM_5709)
        {
            offset = 0x80;
        }
        else
        {
            // offset = WORD_ALIGNED_OFFSETOF(l4_context_t, l4ctx_ctx_type);
            offset = 0;
        }

        CTX_WR(pdev, txq->cid_addr, offset, val);

        if (CHIP_NUM(pdev) == CHIP_NUM_5709)
        {
            offset = 0x240;
        }
        else
        {
            // offset = WORD_ALIGNED_OFFSETOF(l4_context_t, l4ctx_cmd);
            offset = 34*sizeof(u32_t);
        }

        val = (CCELL_CMD_TYPE_TYPE_L2 | ((LM_PAGE_BITS-8) << 4)) << 24;
        val |= 8 << 16;
        CTX_WR(pdev, txq->cid_addr, offset, val);

        val = txq->bd_chain_phy.as_u32.high;
        CTX_WR(
            pdev,
            txq->cid_addr,
            offset + WORD_ALIGNED_OFFSETOF(
                tcp_context_cmd_cell_te_t, ccell_tbdr_bhaddr.hi),
            val);

        val = txq->bd_chain_phy.as_u32.low;
        CTX_WR(
            pdev,
            txq->cid_addr,
            offset + WORD_ALIGNED_OFFSETOF(
                tcp_context_cmd_cell_te_t, ccell_tbdr_bhaddr.lo),
            val);

    }
} /* init_l2txq */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_l2rxq(
    lm_device_t *pdev)
{
    lm_rx_chain_t *rxq;
    u32_t bd_page_cnt;
    u32_t idx;
    u32_t val;

    for(idx = 0; idx < sizeof(lm_rx_stats_t)/sizeof(u32_t); idx++)
    {
        ((u32_t *) &pdev->rx_info.stats)[idx] = 0;
    }

    for(idx = 0; idx < pdev->rx_info.num_rxq; idx++)
    {
        rxq = &pdev->rx_info.chain[idx];

        bd_page_cnt = pdev->params.l2_rx_bd_page_cnt[rxq->idx];

        rxq->prod_idx = 0;
        rxq->con_idx = 0;
        rxq->prod_bseq = 0;
        rxq->prod_bd = rxq->bd_chain_virt;
        rxq->bd_left = bd_page_cnt * MAX_BD_PER_PAGE - 1;

        if(bd_page_cnt == 0)
        {
            continue;
        }

        lm_setup_bd_chain_ring(
            (u8_t *) rxq->bd_chain_virt,
            rxq->bd_chain_phy,
            bd_page_cnt);

        val = L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE << 24;
        val |= (((sizeof(l2_bd_chain_context_t) + 0x1f) & ~0x1f) / 0x20) << 16;
        val |= 0x02 << 8;
        CTX_WR(
            pdev,
            rxq->cid_addr,
            WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_ctx_type),
            val);

        val = rxq->bd_chain_phy.as_u32.high;
        CTX_WR(
            pdev,
            rxq->cid_addr,
            WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_nx_bdhaddr_hi),
            val);

        val = rxq->bd_chain_phy.as_u32.low;
        CTX_WR(
            pdev,
            rxq->cid_addr,
            WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_nx_bdhaddr_lo),
            val);

        //  In case we are coming out from hibernation, we need to restore
        //  previous MTU setting. Otherwise, we would initialize max packet
        //  length to default (i.e. initial power-up)
        CTX_WR(
            pdev,
            rxq->cid_addr,
            WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_max_pkt_len),
            rxq->max_pkt_len ?
                rxq->max_pkt_len:
                pdev->params.mtu + 4);  // + 4 L2CRC


    }
} /* init_l2rxq */



#ifndef EXCLUDE_KQE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_kq(
    lm_device_t *pdev)
{
    lm_kq_info_t *kq;
    u32_t page_cnt;
    u32_t val;

    kq = &pdev->kq_info;

    /* initialize kwq. */
    page_cnt = pdev->params.kwq_page_cnt;
    if(page_cnt)
    {
        kq->kwq_cid_addr = GET_CID_ADDR(KWQ_CID);
        kq->kwqe_left = (LM_PAGE_SIZE/sizeof(kwqe_t)) * page_cnt - 1;
        kq->kwq_last_qe = kq->kwq_virt + kq->kwqe_left;

        setup_page_table(kq->kwq_pgtbl_virt, page_cnt, kq->kwq_phy);

        kq->kwq_prod_idx = 0;
        kq->kwq_con_idx = 0;
        kq->kwq_prod_qe = kq->kwq_virt;
        kq->kwq_con_qe = kq->kwq_virt;
        kq->kwqe_left = (LM_PAGE_SIZE/sizeof(kwqe_t)) * page_cnt - 1;

        val = KRNLQ_TYPE_TYPE_KRNLQ << 24;
        val |= (((sizeof(krnlq_context_t) + 0x1f) & ~0x1f) / 0x20) << 16;
        val |= LM_PAGE_BITS-8;
        val |= KRNLQ_FLAGS_QE_SELF_SEQ;
        CTX_WR(
            pdev,
            kq->kwq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_type),
            val);

        val = (LM_PAGE_SIZE/sizeof(kwqe_t) - 1) << 16;
        CTX_WR(
            pdev,
            kq->kwq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_qe_self_seq_max),
            val);

        val = (LM_PAGE_SIZE/sizeof(kwqe_t)) << 16;
        val |= pdev->params.kwq_page_cnt;
        CTX_WR(
            pdev,
            kq->kwq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_pgtbl_npages),
            val);

        val = kq->kwq_pgtbl_phy.as_u32.high;
        CTX_WR(
            pdev,
            kq->kwq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_pgtbl_haddr_hi),
            val);

        val = kq->kwq_pgtbl_phy.as_u32.low;
        CTX_WR(
            pdev,
            kq->kwq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_pgtbl_haddr_lo),
            val);
    }

    /* initialize kcq. */
    page_cnt = pdev->params.kcq_page_cnt;
    if(page_cnt)
    {
        kq->kcq_cid_addr = GET_CID_ADDR(KCQ_CID);
        kq->kcq_last_qe = kq->kcq_virt +
            (LM_PAGE_SIZE/sizeof(kcqe_t)) * page_cnt - 1;

        setup_page_table(kq->kcq_pgtbl_virt, page_cnt, kq->kcq_phy);

        kq->kcq_con_idx = 0;
        kq->history_kcq_con_idx = 0;
        kq->kcq_con_qe = kq->kcq_virt;
        kq->history_kcq_con_qe = kq->kcq_virt;

        val = KRNLQ_TYPE_TYPE_KRNLQ << 24;
        val |= (((sizeof(krnlq_context_t) + 0x1f) & ~0x1f) / 0x20) << 16;
        val |= LM_PAGE_BITS-8;
        val |= KRNLQ_FLAGS_QE_SELF_SEQ;
        CTX_WR(
            pdev,
            kq->kcq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_type),
            val);

        val = (LM_PAGE_SIZE/sizeof(kwqe_t) - 1) << 16;
        CTX_WR(
            pdev,
            kq->kcq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_qe_self_seq_max),
            val);

        val = (LM_PAGE_SIZE/sizeof(kcqe_t)) << 16;
        val |= pdev->params.kcq_page_cnt;
        CTX_WR(
            pdev,
            kq->kcq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_pgtbl_npages),
            val);

        val = kq->kcq_pgtbl_phy.as_u32.high;
        CTX_WR(
            pdev,
            kq->kcq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_pgtbl_haddr_hi),
            val);

        val = kq->kcq_pgtbl_phy.as_u32.low;
        CTX_WR(
            pdev,
            kq->kcq_cid_addr,
            WORD_ALIGNED_OFFSETOF(krnlq_context_t, krnlq_pgtbl_haddr_lo),
            val);
    }
} /* init_kq */
#endif /* EXCLUDE_KQE_SUPPORT */

/*******************************************************************************
 * Description:  Determines the flow control, MAC, and CU trip values
 *
 * xoff = processing_q_delay + propagation_delay + response_delay +
 *        propagation_delay for return path + drop_margin_delay
 * xon = xoff + (mtu/mbuf_size)
 *
 * MAC_drop = drop_margin_low*mtu/mbuf_size
 * MAC_keep = drop_margin_high*mtu/mbuf_size
 *
 * CU_drop =  (drop_margin_low+1)*mtu/mbuf_size
 * CU_keep =  (drop_margin_high)*mtu/mbuf_size
 *
 * processing_q_delay = ((mtu+20)/(64+20))+1)
 * propagation_delay = 1
 * response_time = 2 (quanta)
 * mbuf_size = 128
 * response_delay = (response_time*512)/(mbuf_size*8) + (mtu/mbuf_size)
 * drop_margin_low = 0.5
 * drop_margin_high = 2.5
 * drop_margin_mid = 1.5
 * drop_margin_delay = (mtu*drop_margin_mid/mbuf_size)
 *
 * Table:
 *
 * Return:  Flow control, MAC, and CU trip values
 ******************************************************************************/
typedef enum
{
    TRIP_FLOW   = 0,
    TRIP_MAC    = 1,
    TRIP_CU     = 2
} trip_type_t;

STATIC void
get_trip_val(
    trip_type_t type,
    u32_t mtu,
    u32_t *val,
    u8_t  enable_cu_rate_limiter,
    u8_t  mbuf_cnt_adj)
{
#define NONJF_MTU_SIZE  1500
#define MTU_STEP        500

    const u32_t trip_tbl[3][2] = {
        /* Base value, Increment */
	{ 0x00410036, 0x00140010 }, /* XOFF/XON setting */
	{ 0x001e0006, 0x000a0002 }, /* MAC drop/keep trip setting */
	{ 0x005e0052, 0x000a0006 } /* CU drop/keep trip setting */
    };

    const u32_t isolate_rbuf_trip_tbl[3][2] = {
        /* Base value, Increment */
	{ 0x0089007e, 0x00140010 }, /* XOFF/XON setting */
	{ 0x0066004e, 0x000a0002 }, /* MAC drop/keep trip setting */
	{ 0x0066004e, 0x000a0006 } /* CU drop/keep trip setting */
    };

    if(type > TRIP_CU)
        type = 0;   /* Crash prevention */

    *val = 0;
    while(mtu > NONJF_MTU_SIZE + MTU_STEP)
    {
        if(enable_cu_rate_limiter)
            *val += isolate_rbuf_trip_tbl[type][1];
        else
            *val += trip_tbl[type][1];

        mtu -= MTU_STEP;
    }
    if(enable_cu_rate_limiter)
        *val = *val + (isolate_rbuf_trip_tbl[type][0] - (mbuf_cnt_adj<<16 | mbuf_cnt_adj));
    else
        *val = *val + trip_tbl[type][0];

} /* get_trip_val */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
zero_out_sb(
    lm_device_t *pdev,
    u32_t *sb_ptr)
{
    u32_t sb_size;
    u32_t offset;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        sb_size = sizeof(status_blk_combined_t);
    }
    else
    {
        sb_size = sizeof(status_block_t);
    }

    offset = 0;

    while(offset < sb_size)
    {
        *sb_ptr = 0;
        sb_ptr++;
        offset += sizeof(u32_t);
    }
} /* zero_out_sb */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
reduce_ftq_depth(
    lm_device_t *pdev)
{
    DbgBreakIf(CHIP_REV(pdev) != CHIP_REV_IKOS &&
               CHIP_REV(pdev) != CHIP_REV_FPGA);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, com.com_comxq_ftq_ctl),
        2 << 12);
    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, com.com_comtq_ftq_ctl),
        2 << 12);
    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, com.com_comq_ftq_ctl),
        2 << 12);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, cp.cp_cpq_ftq_ctl),
        4 << 12);

    REG_WR(pdev, csch.csch_ch_ftq_ctl, 8 << 12);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, mcp.mcp_mcpq_ftq_ctl),
        32 << 12);

    REG_WR(pdev, rdma.rdma_ftq_ctl, 2 << 12);

    REG_WR(pdev, rlup.rlup_ftq_ctl, 8 << 12);

    REG_WR(pdev, rv2p.rv2p_pftq_ctl, 2 << 12);
    REG_WR(pdev, rv2p.rv2p_tftq_ctl, 2 << 12);
    REG_WR(pdev, rv2p.rv2p_mftq_ctl, 4 << 12);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, rxp.rxp_cftq_ctl),
        8 << 12);
    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, rxp.rxp_ftq_ctl),
        8 << 12);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, tas.tas_ftq_ctl),
        16 << 12);

    REG_WR(pdev, tbdr.tbdr_ftq_ctl, 2 << 12);

    REG_WR(pdev, tdma.tdma_ftq_ctl, 2 << 12);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, tpat.tpat_ftq_ctl),
        16 << 12);

    REG_WR(pdev, tsch.tsch_ftq_ctl, 2 << 12);

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, txp.txp_ftq_ctl),
        2 << 12);
} /* reduce_ftq_depth */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_5709_for_msix(
    lm_device_t *pdev)
{
    u32_t val;

    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);

    REG_WR(pdev,
           pci.pci_grc_window_addr,
           (pdev->hw_info.shmem_base & ~0x7fff) |
            PCI_GRC_WINDOW_ADDR_SEP_WIN);

    REG_WR(pdev,
           pci.pci_grc_window1_addr,
           (pdev->hw_info.shmem_base & ~0x7fff) + 0x6000 /*0x16e000 */);

    REG_RD(pdev, pci_config.pcicfg_msix_control, &val);
    switch(pdev->vars.interrupt_mode)
    {
        case IRQ_MODE_MSIX_BASED:
            /* enable all msix vectors */
            REG_WR(pdev,
                hc.hc_msix_bit_vector,
                HC_MSIX_BIT_VECTOR_VAL);
        break;

        case IRQ_MODE_MSI_BASED:
            /* enable 16 messages so hardware will
             * generate maximum of 9 messages
             */
            REG_RD(pdev,
                   pci_config.pcicfg_msi_control,
                   &val);
            val &= PCICFG_MSI_CONTROL_MENA;
            val |= PCICFG_MSI_CONTROL_MENA_16;
            REG_WR(pdev,
                   pci_config.pcicfg_msi_control,
                   (u16_t)val);
        break;

        case IRQ_MODE_SIMD:
            /* tell the chip that we are in single isr/multiple dpc mode */
            if(val & PCICFG_MSIX_CONTROL_MSIX_ENABLE)
            {
                u32_t idx, addr_l, addr_h, vec_data;

                REG_WR(pdev,
                       hc.hc_msix_bit_vector,
                       HC_MSIX_BIT_VECTOR_VAL);

                REG_RD_IND(
                    pdev,
                    OFFSETOF(reg_space_t, hc1.hc1_msix_vector0_addr_l),
                    &addr_l);
                REG_RD_IND(
                    pdev,
                    OFFSETOF(reg_space_t, hc1.hc1_msix_vector0_addr_h),
                    &addr_h);
                REG_RD_IND(
                    pdev,
                    OFFSETOF(reg_space_t, hc1.hc1_msix_vector0_data),
                    &vec_data);
                for(idx = 1; idx < 9; idx++)
                {
                    REG_WR_IND(
                        pdev,
                        OFFSETOF(reg_space_t,
                                 hc1.hc1_msix_vector0_addr_l) +
                                 idx*4*sizeof(u32_t),
                        addr_l);
                    REG_WR_IND(
                        pdev,
                        OFFSETOF(reg_space_t,
                                 hc1.hc1_msix_vector0_addr_h) +
                                 idx*4*sizeof(u32_t),
                        addr_h);
                    REG_WR_IND(
                        pdev,
                        OFFSETOF(reg_space_t,
                                 hc1.hc1_msix_vector0_data) +
                                 idx*4*sizeof(u32_t),
                        vec_data);
                }
            }
            else
            {
                REG_RD(pdev,
                       pci_config.pcicfg_msi_control,
                       &val);
                val &= ~PCICFG_MSI_CONTROL_MENA;
                REG_WR(pdev,
                       pci_config.pcicfg_msi_control,
                       (u16_t)val);
            }
        break;

        case IRQ_MODE_LINE_BASED:
            /* do nothing */
        break;

        default:
            DbgBreakMsg("Unknown interrupt mode\n");
            break;
    }

    REG_WR(pdev,
           pci.pci_grc_window2_addr,
           MSIX_TABLE_ADDR /*MSIX vector addr */);
    REG_WR(pdev,
           pci.pci_grc_window3_addr,
           MSIX_PBA_ADDR /*MSIX PBA addr */);
    REG_WR(pdev, pci.pci_msix_tbl_off_bir, PCI_GRC_WINDOW2_BASE);
    REG_WR(pdev, pci.pci_msix_pba_off_bit, PCI_GRC_WINDOW3_BASE);
} /* init_5709_for_msix */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_hc(
    lm_device_t *pdev)
{
    u32_t val;

    /* Set HC timer mode. */
    REG_RD(pdev, hc.hc_config, &val);
    val &= ~(HC_CONFIG_RX_TMR_MODE | HC_CONFIG_TX_TMR_MODE |
        HC_CONFIG_COM_TMR_MODE | HC_CONFIG_CMD_TMR_MODE);

    if(pdev->params.hc_timer_mode & HC_RX_TIMER_MODE)
    {
        val |= HC_CONFIG_RX_TMR_MODE;
    }

    if(pdev->params.hc_timer_mode & HC_TX_TIMER_MODE)
    {
        val |= HC_CONFIG_TX_TMR_MODE;
    }

    if(pdev->params.hc_timer_mode & HC_COM_TIMER_MODE)
    {
        val |= HC_CONFIG_COM_TMR_MODE;
    }

    if(pdev->params.hc_timer_mode & HC_CMD_TIMER_MODE)
    {
        val |= HC_CONFIG_CMD_TMR_MODE;
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        val &= ~HC_CONFIG_SET_MASK_AT_RD;
        //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
        //{
        //    val |= HC_CONFIG_ONE_SHOT;
        //}
    }

    REG_WR(pdev, hc.hc_config, val);

    /* Enable timer abort a attention which is used to request
     * the driver to write a driver pulse to the firmware. */
    REG_RD(pdev, hc.hc_attn_bits_enable, &val);
    val |= STATUS_ATTN_BITS_TIMER_ABORT;
    REG_WR(pdev, hc.hc_attn_bits_enable, val);

    /* Set HC parameters. */
    REG_WR(pdev, hc.hc_status_addr_l, pdev->vars.status_phy.as_u32.low);
    REG_WR(pdev, hc.hc_status_addr_h, pdev->vars.status_phy.as_u32.high);

    REG_WR(pdev, hc.hc_statistics_addr_l, pdev->vars.stats_phy.as_u32.low);
    REG_WR(pdev, hc.hc_statistics_addr_h, pdev->vars.stats_phy.as_u32.high);

    REG_WR(
        pdev,
        hc.hc_tx_quick_cons_trip,
        (pdev->params.tx_quick_cons_trip_int << 16) |
            pdev->params.tx_quick_cons_trip);
    REG_WR(
        pdev,
        hc.hc_rx_quick_cons_trip,
        (pdev->params.rx_quick_cons_trip_int << 16) |
            pdev->params.rx_quick_cons_trip);
    REG_WR(
        pdev,
        hc.hc_comp_prod_trip,
        (pdev->params.comp_prod_trip_int << 16) |
            pdev->params.comp_prod_trip);
    REG_WR(
        pdev,
        hc.hc_tx_ticks,
        (pdev->params.tx_ticks_int << 16) |
            pdev->params.tx_ticks);
    REG_WR(
        pdev,
        hc.hc_rx_ticks,
        (pdev->params.rx_ticks_int << 16) |
            pdev->params.rx_ticks);
    REG_WR(
        pdev,
        hc.hc_com_ticks,
        (pdev->params.com_ticks_int << 16) |
            pdev->params.com_ticks);
    REG_WR(
        pdev, hc.hc_cmd_ticks,
        (pdev->params.cmd_ticks_int << 16) |
            pdev->params.cmd_ticks);

    val = pdev->params.stats_ticks;
    if(CHIP_REV(pdev) == CHIP_REV_IKOS)
    {
        val = val / 1000;
        if(val < 0x100)
        {
            val = 0x100;
        }
    }
    REG_WR(pdev, hc.hc_stats_ticks, val);

    REG_WR(pdev, hc.hc_stat_collect_ticks, 0xbb8);  /* 3ms */
    REG_WR(pdev, hc.hc_command, HC_COMMAND_CLR_STAT_NOW);
} /* init_hc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_hc_for_5709(
    lm_device_t *pdev)
{
    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);

    init_hc(pdev);

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_1, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_1, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_1, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_1, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_1, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_1, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_1, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_1, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_1, &val);
    //    val |= HC_SB_CONFIG_1_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_1, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_2, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_2, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_2, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_2, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_2, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_2, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_2, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_2, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_2, &val);
    //    val |= HC_SB_CONFIG_2_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_2, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_3, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_3, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_3, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_3, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_3, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_3, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_3, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_3, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_3, &val);
    //    val |= HC_SB_CONFIG_3_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_3, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_4, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_4, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_4, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_4, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_4, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_4, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_4, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_4, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_4, &val);
    //    val |= HC_SB_CONFIG_4_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_4, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_5, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_5, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_5, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_5, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_5, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_5, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_5, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_5, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_5, &val);
    //    val |= HC_SB_CONFIG_5_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_5, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_6, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_6, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_6, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_6, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_6, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_6, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_6, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_6, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_6, &val);
    //    val |= HC_SB_CONFIG_6_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_6, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_7, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_7, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_7, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_7, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_7, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_7, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_7, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_7, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_7, &val);
    //    val |= HC_SB_CONFIG_7_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_7, val);
    //}

    REG_WR(pdev, hc.hc_tx_quick_cons_trip_8, pdev->params.psb_tx_cons_trip);
    REG_WR(pdev, hc.hc_tx_ticks_8, pdev->params.psb_tx_ticks);
    REG_WR(pdev, hc.hc_rx_quick_cons_trip_8, pdev->params.psb_rx_cons_trip);
    REG_WR(pdev, hc.hc_rx_ticks_8, pdev->params.psb_rx_ticks);
    REG_WR(pdev, hc.hc_comp_prod_trip_8, pdev->params.psb_comp_prod_trip);
    REG_WR(pdev, hc.hc_com_ticks_8, pdev->params.psb_com_ticks);
    REG_WR(pdev, hc.hc_cmd_ticks_8, pdev->params.psb_cmd_ticks);
    REG_WR(pdev, hc.hc_periodic_ticks_8, pdev->params.psb_period_ticks);
    //if(pdev->vars.interrupt_mode > IRQ_MODE_SIMD)
    //{
    //    REG_RD(pdev, hc.hc_sb_config_8, &val);
    //    val |= HC_SB_CONFIG_8_ONE_SHOT;
    //    REG_WR(pdev, hc.hc_sb_config_8, val);
    //}
} /* init_hc_for_5709 */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_hc_for_57728(
    lm_device_t *pdev)
{
    init_hc(pdev);
    init_hc_for_5709(pdev);

    #if X1V_havhavhav
    REG_WR(pdev, hc.hc_sb_haddr_0_lo, pdev->vars.status_phy.as_u32.low);
    REG_WR(pdev, hc.hc_sb_haddr_0_hi, pdev->vars.status_phy.as_u32.high);

    REG_WR(pdev, hc.hc_sb_select_0_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 0);
    REG_WR(pdev, hc.hc_sb_select_1_config,
            ENABLE | fid == 1 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 7);
    REG_WR(pdev, hc.hc_sb_select_2_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 2);
    REG_WR(pdev, hc.hc_sb_select_3_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 3);
    REG_WR(pdev, hc.hc_sb_select_4_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 4);
    REG_WR(pdev, hc.hc_sb_select_5_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 5);
    REG_WR(pdev, hc.hc_sb_select_6_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 6);
    REG_WR(pdev, hc.hc_sb_select_7_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 7);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 8);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 9);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 10);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 11);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 12);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 13);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 14);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 15);
    REG_WR(pdev, hc.hc_sb_select_8_config,
            ENABLE | fid == 7 | param-sel = 0 | haddr_sel = 0 |
            haddr_idx_sel = 16);
    #endif
} /* init_hc_for_57728 */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/

// Refer to TetonII Register spec, setting bits in krl_???_mask1 and
// krl_???_mask2 will cause the corresponding engine (CP or RV2P) to be
// activated when any word enabled by this mask is written. Mask1 is
// for first 128 bytes and mask2 is for second 128 bytes.
// Each bit in the mask correspond to a 32 bit word in the kernal area.
// e.g. Writing 0x2000 to the mask2 means activating the engine
// when context location 0xB4 is being written
// (i.e. (0xB4 - 128)/sizeof(u32_t) = bit 13
#define KNL_L4_MASK(field)    \
    (1<<(OFFSETOF(l4_context_t, l4ctx_l4_bd_chain_##field) & ~0x80)/sizeof(u32_t))

#define KNL_L5_MASK(field)    \
    (1<<(OFFSETOF(l5_context_t, l5ctx_##field) & ~0x80)/sizeof(u32_t))

lm_status_t
lm_reset_setup(
    lm_device_t *pdev,
    u32_t reset_reason)
{
    u32_t val;
    u8_t  mbuf_adj = 0;

    lm_chip_reset(pdev, reset_reason);

    /* Teton family of chips does not support PCI-X relax ordering. */
    if(pdev->hw_info.bus_mode == BUS_MODE_PCIX)
    {
        REG_RD_OFFSET(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_pcix_cap_id),
            &val);
        val &= ~(PCICFG_PCIX_COMMAND_RELAX_ORDER << 16);
        REG_WR_OFFSET(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_pcix_cap_id),
            val);
    }

    /* 5709 devices have interrupts enabled by default
     * after a hardware reset.  Disable them.
     */
    lm_disable_int(pdev);

    /* The linkready signal going to the MAC is qualified by a port
     * mode of GMII or MII.  When the port mode is NONE, the linkready
     * signal is always deasserted when when link is active.  Thus for
     * us to get a link change event, we need to set the port mode to
     * something other than NONE.  This logic may change in future
     * version of the chip.
     *
     * Also when the port mode is set NONE, the register read/write
     * to the emac block (0x1408) will cause the TETON-II FPGA to
     * lock up.  This is not seen with the original TETON FPGA. */
    REG_WR(pdev, emac.emac_mode, EMAC_MODE_EXT_LINK_POL | EMAC_MODE_PORT_GMII);

    /* Setup DMA configuration. The swap settings are what the device will
     * will do, not the net result you want.  This is because there could
     * be swapping by intermediary devices (pci bridges). */
    val = DMA_CONFIG_DATA_BYTE_SWAP_TE |
        DMA_CONFIG_DATA_WORD_SWAP_TE |
        DMA_CONFIG_CNTL_WORD_SWAP_TE |
#ifdef BIG_ENDIAN
        DMA_CONFIG_CNTL_BYTE_SWAP_TE |
#endif
        (pdev->params.num_rchans & 0xf) << 12 |
        (pdev->params.num_wchans & 0xf) << 16;

    /* Workaround for data corruption on Intel 840/860 chipset. */
    if(pdev->params.ping_pong_dma)
    {
        val |= DMA_CONFIG_CNTL_PING_PONG_DMA_TE;
    }

    /* Apply workaround to avoid race condition in DMA completion
     * and write to DMA buffer memory.  This configuration should be
     * enabled on all versions of 5706.  */
    val |= (0x2<<20) | (1<<11);

    /* Enable delayed completion. */
    if(pdev->hw_info.bus_mode == BUS_MODE_PCIX &&
        pdev->hw_info.bus_speed == BUS_SPEED_133_MHZ &&
        CHIP_ID(pdev) != CHIP_ID_5706_A0)
    {
        val |= 1 << 23;
    }

    /* Configure the clock ratio in the FPGA mode. */
    if(CHIP_REV(pdev) == CHIP_REV_FPGA)
    {
        val |= 0x100;
    }

    REG_WR(pdev, dma.dma_config, val);

    if(pdev->params.one_tdma)
    {
        REG_RD(pdev, tdma.tdma_config, &val);
        val |= TDMA_CONFIG_ONE_DMA;
        REG_WR(pdev, tdma.tdma_config, val);
    }

    if(CHIP_REV(pdev) == CHIP_REV_FPGA)
    {
        REG_RD(pdev, pci.pci_config_2, &val);
        val &= ~0x02000000;
        REG_WR(pdev, pci.pci_config_2, val);
    }

    /* We need to enable the context block so we can initialize context
     * memory.
     *
     * We also need to enable HC so it can record the link state and the
     * first status block update we get will reflect the current state.
     *
     * We need to enable RV2P in order to download the firmwares for
     * its two processors. */
    REG_WR(
        pdev,
        misc.misc_enable_set_bits,
        MISC_ENABLE_SET_BITS_HOST_COALESCE_ENABLE |
            MISC_ENABLE_STATUS_BITS_RX_V2P_ENABLE |
            MISC_ENABLE_SET_BITS_DMA_ENGINE_ENABLE |
            MISC_ENABLE_STATUS_BITS_CONTEXT_ENABLE);

    /* Initialize context mapping and zero out the quick contexts.  The
     * context block must have already been enabled. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A0)
    {
        init_context_5706_a0_wa(pdev);
    }
    else if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        init_context_5706(pdev);
    }
    else if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        init_context_5709(pdev);
        #if 0
        /* Temporary L4 fix. */
        // if(CHIP_ID(pdev) == CHIP_ID_5709_IKOS ||
        //    CHIP_ID(pdev) == CHIP_ID_5709_FPGA)
        {
            REG_WR(pdev, mq.mq_map_l4_0, 0x8001c1b9);
        }
        #endif

        REG_WR(pdev, mq.mq_map_l4_0, 0x80010db9);
        REG_WR(pdev, mq.mq_map_l4_4, 0x82810eb2);
        REG_WR(pdev, mq.mq_map_l4_5, 0x8f0113b4);
    }
    else
    {
        DbgBreakIf(1);
    }

    if(pdev->params.test_mode & TEST_MODE_XDIAG_ISCSI)
    {
        lm_init_cpus(pdev, CPU_RV2P_1 | CPU_RV2P_2); /* other CPUs are loaded through TCL */
    }
    else
    {
        lm_init_cpus(pdev, CPU_ALL);
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD_IND(
            pdev,
            OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+
            RXP_HSI_OFFSETOFF(hw_filter_ctx_offset),
            &pdev->vars.hw_filter_ctx_offset);

        init_5709_for_msix(pdev);
    }

    lm_nvram_init(pdev, FALSE);

    /* tcp_syn_dos_defense - let the firmware route all the packets with
     * TCP SYN bit set to rx chain #1. */
    REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(tcp_syn_dos_defense),
            pdev->params.enable_syn_rcvq);

    REG_RD(pdev, mq.mq_config, &val);
    val &= ~MQ_CONFIG_KNL_BYP_BLK_SIZE;
    switch((LM_PAGE_BITS - 8) << 4)
    {
        case MQ_CONFIG_KNL_BYP_BLK_SIZE_256:
            val |= MQ_CONFIG_KNL_BYP_BLK_SIZE_256;
            break;

        case MQ_CONFIG_KNL_BYP_BLK_SIZE_512:
            val |= MQ_CONFIG_KNL_BYP_BLK_SIZE_512;
            break;

        case MQ_CONFIG_KNL_BYP_BLK_SIZE_1K:
            val |= MQ_CONFIG_KNL_BYP_BLK_SIZE_1K;
            break;

        case MQ_CONFIG_KNL_BYP_BLK_SIZE_2K:
            val |= MQ_CONFIG_KNL_BYP_BLK_SIZE_2K;
            break;

        case MQ_CONFIG_KNL_BYP_BLK_SIZE_4K:
            val |= MQ_CONFIG_KNL_BYP_BLK_SIZE_4K;
            break;

        default:
            DbgBreakMsg("Not supported page size.\n");
            break;
    }

    if(pdev->params.bin_mq_mode)
    {
        DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);

        val |= MQ_CONFIG_BIN_MQ_MODE;
    }

    REG_WR(pdev, mq.mq_config, val);

    /* Configure the end of the kernel mailboxq window and the start of the
     * kernel bypass mailboxq. */
    val = 0x10000 + (MAX_CID_CNT * MB_KERNEL_CTX_SIZE);
    REG_WR(pdev, mq.mq_knl_byp_wind_start, val);
    REG_WR(pdev, mq.mq_knl_wind_end, val);

    /* Configure page size. */
    REG_RD(pdev, tbdr.tbdr_config, &val);
    val &= ~TBDR_CONFIG_PAGE_SIZE;
    val |= (LM_PAGE_BITS - 8) << 24 | 0x40;
    REG_WR(pdev, tbdr.tbdr_config, val);

    /* Program the MTU.  Also include 4 bytes for CRC32. */
    val = pdev->params.mtu+4;
    if(pdev->params.mtu > MAX_ETHERNET_PACKET_SIZE)
    {
        val |= EMAC_RX_MTU_SIZE_JUMBO_ENA;
    }
    REG_WR(pdev, emac.emac_rx_mtu_size, val);

    if(pdev->vars.enable_cu_rate_limiter)
    {
        if(pdev->vars.cu_mbuf_cnt > 0x48)
        {
            /* only allow cu mbuf cluster cnt up to 0x48 to accomodate jumbo
             * frame size of 9018 ( note: each mbuf cluster is 128 bytes) */
            pdev->vars.cu_mbuf_cnt = 0x48;
        }

        if(pdev->vars.cu_mbuf_cnt == 0)
        {
            /* chip default use 8k cu mbuf */
            mbuf_adj = 0x48 - 0x40;
        }
        else
        {
            mbuf_adj = 0x48 - pdev->vars.cu_mbuf_cnt;
        }
    }
    /* Added flow control trip setup, JF or non-JF */
    get_trip_val(
        TRIP_FLOW,
        pdev->params.mtu,
        &val,
        pdev->vars.enable_cu_rate_limiter,
        mbuf_adj);

    REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_config),
            val);

    get_trip_val(
        TRIP_MAC,
        pdev->params.mtu,
        &val,
        pdev->vars.enable_cu_rate_limiter,
        mbuf_adj);

    REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_config2),
            val);

    if(!pdev->vars.enable_cu_rate_limiter)
    {
        get_trip_val(TRIP_CU, pdev->params.mtu, &val, 0, 0);
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_config3),
            val);
    }
    else
    {
        /* isolate catchup traffic rbuf from normal traffic */
        REG_RD_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_command),
            &val);
        val |= RBUF_COMMAND_CU_ISOLATE_XI;
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rbuf.rbuf_command),
            val);

        REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, rbuf.rbuf_config3),
                0);
        if(pdev->vars.cu_mbuf_cnt)
        {
            val = pdev->vars.cu_mbuf_cnt;
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, rbuf.rbuf_cu_buffer_size),
                val);
        }
        else
        {
            /* get default cu_mbuf_cnt from chip */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rbuf.rbuf_cu_buffer_size),
                &val);
        }
        /*account for initial MBUF allocated by the RPC*/
        val -= 1;
        val *= 128;
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_cu_buf_size),
            val);
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(cu_rate_limiter_enable),
            1);
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, txp.txp_scratch[0])+TXP_HSI_OFFSETOFF(cu_rate_limiter_enable),
            1);
        REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(cu_rate_limiter_enable),
            1);
    }

    /* Set up how to generate a link change interrupt. */
    if(pdev->params.phy_int_mode == PHY_INT_MODE_MI_INTERRUPT)
    {
        REG_WR(pdev, emac.emac_attention_ena, EMAC_ATTENTION_ENA_MI_INT);
    }
    else if(pdev->params.phy_int_mode == PHY_INT_MODE_LINK_READY)
    {
        REG_WR(pdev, emac.emac_attention_ena, EMAC_ATTENTION_ENA_LINK);
    }
    else if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        REG_WR(pdev, emac.emac_attention_ena, EMAC_ATTENTION_ENA_LINK);

        REG_RD(pdev, emac.emac_mdio_mode, &val);
        val |= EMAC_MDIO_MODE_AUTO_POLL;
        REG_WR(pdev, emac.emac_mdio_mode, val);
    }
    else
    {
        DbgBreakMsg("Invalid phy_int_mode.\n");
    }

    zero_out_sb(pdev, (u32_t *) pdev->vars.status_virt);

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 ||
        CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        init_hc(pdev);
    }
    else if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        init_hc_for_5709(pdev);
    }
    else if(CHIP_NUM(pdev) == CHIP_NUM_57728)
    {
        init_hc_for_57728(pdev);
    }
    else
    {
        DbgBreakMsg("### Invalid chip number.\n");
    }

    if(CHIP_REV(pdev) == CHIP_REV_IKOS || CHIP_REV(pdev) == CHIP_REV_FPGA)
    {
        reduce_ftq_depth(pdev);
    }

    init_l2txq(pdev);
    init_l2rxq(pdev);

    #ifndef EXCLUDE_KQE_SUPPORT
    init_kq(pdev);
    #endif

    #if INCLUDE_OFLD_SUPPORT
    l4_reset_setup(pdev);
    #endif

    /* Enable Commnad Scheduler notification when we write to the
     * host producer index of the kernel contexts. */
    REG_WR(pdev, mq.mq_knl_cmd_mask1, KNL_L5_MASK(sq_pidx));

    /* Enable Command Scheduler notification when we write to either
     * the Send Queue or Receive Queue producer indexes of the kernel
     * bypass contexts. */
    REG_WR(pdev, mq.mq_knl_byp_cmd_mask1, KNL_L5_MASK(cq_cidx)|
                                          KNL_L5_MASK(sq_pidx)|
                                          KNL_L5_MASK(rq_pidx));
    REG_WR(pdev, mq.mq_knl_byp_write_mask1,  KNL_L5_MASK(cq_cidx)|
                                             KNL_L5_MASK(sq_pidx)|
                                             KNL_L5_MASK(rq_pidx));

    /* Use kernel mailbox for L5 context (iSCSI and rdma). */
    REG_WR(pdev, mq.mq_knl_cmd_mask1,   KNL_L5_MASK(cq_cidx)|
                                        KNL_L5_MASK(sq_pidx)|
                                        KNL_L5_MASK(rq_pidx));
    REG_WR(pdev, mq.mq_knl_write_mask1,  KNL_L5_MASK(cq_cidx)|
                                         KNL_L5_MASK(sq_pidx)|
                                         KNL_L5_MASK(rq_pidx));
#ifndef L2_ONLY
    if(CHIP_NUM(pdev) != CHIP_NUM_5709)
    {
        /* Notify CP when the driver post an application buffer. (i.e. writing to host_bseq) */
        REG_WR(pdev, mq.mq_knl_cmd_mask2, KNL_L4_MASK(host_bseq));
    }
    else  // CHIP_NUM_5709
    {
        /* Notify RV2P when the driver post an application buffer. (i.e. writing to host_bseq) */
        REG_WR(pdev, mq.mq_knl_rx_v2p_mask2, KNL_L4_MASK(host_bseq));
    }
#endif
    #ifndef EXCLUDE_KQE_SUPPORT
    /* fw_doorbell - These two processors polls the doorbell for a non zero
     * value before running.  This must be done after setting up the kernel
     * queue contexts. */
    if(pdev->params.kcq_page_cnt)
    {
        REG_WR_IND(pdev, OFFSETOF(reg_space_t, cp.cp_scratch[0])+CP_HSI_OFFSETOFF(fw_doorbell), 1);
        REG_WR_IND(pdev, OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(fw_doorbell), 1);

        mm_wait(pdev, 5);
    }
    #endif

    /* get information from firmware-configured mq.mq_config2. */
    if(pdev->params.bin_mq_mode)
    {
        REG_RD(pdev, mq.mq_config2, &val);

        pdev->hw_info.first_l4_l5_bin = (u16_t) (val & MQ_CONFIG2_FIRST_L4L5);
        pdev->hw_info.bin_size = (u8_t) (val & MQ_CONFIG2_CONT_SZ) >> 3;
    }

    /* Configure page size and start the RV2P processors. */
    val = (LM_PAGE_BITS - 8) << 24;
    REG_WR(pdev, rv2p.rv2p_config, val);

    /* Setup the MAC for the current link settings.  The HC should be already
     * enabled.  We need to enable it so it is aware of the current link
     * state and link acknowledgement (via the call below).  The first
     * status block update we get will reflect the current link state. */
    lm_service_phy_int(pdev, TRUE);

    return LM_STATUS_SUCCESS;
} /* lm_reset_setup */



#if INCLUDE_OFLD_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
enable_alt_catchup(
    lm_device_t *pdev)
{
    l4_kwqe_enable_alt_catchup_t *alt_catchup_kwqe;
    kwqe_t *prod_qe;
    u16_t prod_idx;

    pdev->kq_info.kwqe_left -= 1;

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    alt_catchup_kwqe = (l4_kwqe_enable_alt_catchup_t *) prod_qe;
    alt_catchup_kwqe->tcp_hdr_flags = TCP_HDR_FLAGS_LAYER_MASK_L4;
    alt_catchup_kwqe->tcp_hdr_opcode = TCP_HDR_OPCODE_VALUE_ENABLE_ALT_CATCHUP;

    /* Advance to the next KWQE. */
    if(prod_qe == pdev->kq_info.kwq_last_qe)
    {
        prod_qe = pdev->kq_info.kwq_virt;
    }
    else
    {
        prod_qe++;
    }
    prod_idx++;

    pdev->kq_info.kwq_prod_qe = prod_qe;
    pdev->kq_info.kwq_prod_idx = prod_idx;

    /* catchup_override - use cid 0x30 (catchup2) instead of tx1 for catcup. */
    REG_WR_IND(
            pdev,
            OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(catchup_overide),
            1);

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);
} /* enable_alt_catchup */
#endif



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_reset_run(
    lm_device_t *pdev)
{
    u32_t max_loop_cnt;
    u32_t idx;

    /* Enable all the state machines including the processors. We could use
     * REG_WR(pdev, misc.misc_command, MISC_COMMAND_ENABLE_ALL) this write
     * but for now we don't want to enable the timer block yet.  This
     * needs to be done by the firmware. */
    REG_WR(pdev, misc.misc_enable_set_bits, 0x15ffffff);

    /* Allow the firmware to run.  How long is the delay? */
    max_loop_cnt = 1000;
    if(CHIP_REV(pdev) == CHIP_REV_IKOS)
    {
        max_loop_cnt = 25000;
    }

    for(idx = 0; idx < max_loop_cnt; idx++)
    {
        mm_wait(pdev, 10);
    }

    #if INCLUDE_OFLD_SUPPORT
    /* 'tx4' (cid 30/31) for catcup. */
    if(pdev->tx_info.cu_idx != TX_CHAIN_IDX1)
    {
        enable_alt_catchup(pdev);
    }
    #endif

    /* Force the first status block update so we can acknowledge the initial
     * link status and service an link change since we last call
     * lm_service_phy_int.  If we need to do this here so that we don't have
     * to service a link change event when later we receive a status
     * block update. */
    REG_WR(pdev, hc.hc_command, HC_COMMAND_COAL_NOW_WO_INT);

    /* Wait for the status block.  In the IKOS environment we need to
     * wait this long.  This delay may be reduced significantly when running
     * on the real chip. */
    mm_wait(pdev, 20);
    if(CHIP_REV(pdev) == CHIP_REV_IKOS)
    {
        for(idx = 0; idx < 100; idx++)
        {
            mm_wait(pdev, 10);
        }
    }

    /* Setup the MAC for the current link settings and acknowledge the
     * current link state if necessary. */
    lm_service_phy_int(pdev, FALSE);

    /* Ensure the status block in host memory reflect the current link
     * state and link acknowledgement. */
    REG_WR(pdev, hc.hc_command, HC_COMMAND_COAL_NOW);

    return LM_STATUS_SUCCESS;
} /* lm_reset_run */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_reset(
    lm_device_t *pdev,
    u32_t reset_reason)
{
    lm_status_t status;

    status = lm_reset_setup(pdev, reset_reason);
    if(status == LM_STATUS_SUCCESS)
    {
        status = lm_reset_run(pdev);
    }

    return status;
} /* lm_reset */
