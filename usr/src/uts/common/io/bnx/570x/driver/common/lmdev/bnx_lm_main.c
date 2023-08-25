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
#if !defined(LINUX) && !defined(SOLARIS)
#include "string.h"     // needed by some OS for memset
#pragma warning(disable:28718)
#endif


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_abort(
    lm_device_t *pdev,
    u32_t abort_op,
    u32_t idx)
{
    if(abort_op == ABORT_OP_RX_CHAIN)
    {
        lm_recv_abort(pdev, idx);
    }
    else if(abort_op == ABORT_OP_TX_CHAIN)
    {
        lm_send_abort(pdev, idx);
    }
    else
    {
        DbgBreakMsg("Invalid abort.\n");
    }
} /* lm_abort */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC char *
val_to_decimal_string(
    char *str_buf,
    u32_t buf_size,
    u32_t val)
{
    u32_t digit;

    if(buf_size == 0)
    {
        return str_buf;
    }

    digit = val % 10;
    val = val / 10;

    if(val)
    {
        buf_size--;
        str_buf = val_to_decimal_string(str_buf, buf_size, val);
    }

    *str_buf = '0' + digit;

    str_buf++;

    return str_buf;
} /* val_to_decimal_string */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
build_ver_string(
    char *str_buf,
    u32_t buf_size,
    u8_t major_ver,
    u8_t minor_ver,
    u8_t rel_num,
    u8_t fix_num)
{
    char *p;

    if(buf_size == 0)
    {
        return 0;
    }

    p = str_buf;

    if(buf_size - (p - str_buf) > 1)
    {
        *p = 'v';
        p++;
    }

    if(buf_size - (p - str_buf) > 1)
    {
        p = val_to_decimal_string(
            p,
            buf_size - (u32_t) PTR_SUB(p, str_buf),
            major_ver);
    }

    if(buf_size - (p - str_buf) > 1)
    {
        *p = '.';
        p++;
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        p = val_to_decimal_string(
            p,
            buf_size - (u32_t) PTR_SUB(p, str_buf),
            minor_ver);
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        *p = '.';
        p++;
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        p = val_to_decimal_string(
            p,
            buf_size - (u32_t) PTR_SUB(p, str_buf),
            rel_num);
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        *p = '.';
        p++;
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        p = val_to_decimal_string(
            p,
            buf_size - (u32_t) PTR_SUB(p, str_buf),
            fix_num);
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        *p = '.';
        p++;
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        #if DBG
        *p = 'd';
        #else
        *p = 'r';
        #endif

        p++;
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        #if DBG
        *p = 'b';
        #else
        *p = 't';
        #endif

        p++;
    }

    if(buf_size - (u32_t) PTR_SUB(p, str_buf) > 1)
    {
        #if DBG
        *p = 'g';
        #else
        *p = 'l';
        #endif

        p++;
    }

    *p = 0;
    p++;

    return (u32_t) PTR_SUB(p, str_buf);
} /* build_ver_string */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
get_max_conns(
    lm_device_t *pdev,
    u32_t *max_toe_conn,
    u32_t *max_iscsi_conn,
    u32_t *max_iscsi_pending_tasks)
{
    u32_t max_lic_conn;
    u32_t max_res_conn;
    u32_t res_flags;

    /* get resource reservation flag. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t,
                dev_info.port_feature_config.resource.res_cfg),
        &res_flags);

    /* get max_lic_conn for toe. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, fw_lic_key.max_toe_conn),
        &max_lic_conn);

    max_lic_conn &= 0xffff;

    if(max_lic_conn)
    {
        max_lic_conn ^= FW_ENCODE_16BIT_PATTERN;

        if(max_lic_conn == 0xffff)
        {
            max_lic_conn = 1024;
        }
    }

    /* get max_res_conn for toe. */
    if(res_flags & RES_RES_CFG_VALID)
    {
        if(res_flags & RES_RES_CFG_L2)
        {
            REG_RD_IND(
                pdev,
                pdev->hw_info.shmem_base +
                    OFFSETOF(shmem_region_t,
                        dev_info.port_feature_config.resource.conn_resource1),
                &max_res_conn);
            /*
             * if(max_res_conn == 0 || !(res_flags & RES_RES_CFG_FCFS_DISABLED))
             * CQ#42214 HH, SK and HYF all agreed on removing the test
             * for max_res_conn == 0
             */
            if (!(res_flags & RES_RES_CFG_FCFS_DISABLED))
            {
                max_res_conn = 1024;
            }
        }
        else
        {
            max_res_conn = 0;
        }
    }
    else
    {
        max_res_conn = 1024;
    }

    *max_toe_conn = (max_lic_conn < max_res_conn) ? max_lic_conn: max_res_conn;

    /* get iscsi pending tasks. */
    if((res_flags & RES_RES_CFG_VALID) && (res_flags & RES_RES_CFG_ISCSI))
    {
        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t,
                    dev_info.port_feature_config.resource.conn_resource3),
            max_iscsi_pending_tasks);

        *max_iscsi_pending_tasks &= RES_CONN_ISCSI_PTASK_MASK;

        if(*max_iscsi_pending_tasks == 0 || *max_iscsi_pending_tasks > 128)
        {
            *max_iscsi_pending_tasks = 128;
        }
    }
    else
    {
        *max_iscsi_pending_tasks = 128;
        *max_iscsi_conn = 0;
    }

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, fw_lic_key.max_iscsi_trgt_conn),
        &max_lic_conn);

    if(max_lic_conn)
    {
        max_lic_conn ^= FW_ENCODE_32BIT_PATTERN;
        max_lic_conn >>= 16;
    }

    *max_iscsi_conn = max_lic_conn;

    /* no license information. */
    if(*max_toe_conn == 0)
    {
        if(pdev->hw_info.svid == 0x103c)        /* HP device. */
        {
            *max_toe_conn = 1024;
        }
        else if(CHIP_REV(pdev) == CHIP_REV_IKOS ||
                CHIP_REV(pdev) == CHIP_REV_FPGA)
        {
            *max_toe_conn = 32;
        }
    }

    /* cq#39856 - iSCSI Device Disappears from System after reboot. */
    if(*max_iscsi_conn == 0)
    {
        if(pdev->hw_info.svid == 0x103c)        /* HP device. */
        {
            *max_iscsi_conn = 1024;
        }
        else if(CHIP_REV(pdev) == CHIP_REV_IKOS ||
                CHIP_REV(pdev) == CHIP_REV_FPGA)
        {
            *max_iscsi_conn = 32;
        }
    }
} /* get_max_conns */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_get_dev_info(
    lm_device_t *pdev)
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
        u32_t fpga_ikos_default;

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
        /*                                 asic     fpga/ikos
           offset                          default  default  min     max */
        { _OFFSET(mtu),                    1500,    1500,    1500,   9018 },
        { _OFFSET(l2_rx_desc_cnt[0]),      200,     150,     0,      0 },
        { _OFFSET(l2_rx_desc_cnt[1]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[2]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[3]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[4]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[5]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[6]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[7]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[8]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[9]),      0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[10]),     0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[11]),     0,       0,       0,      0 },
        #if 0
        { _OFFSET(l2_rx_desc_cnt[12]),     0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[13]),     0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[14]),     0,       0,       0,      0 },
        { _OFFSET(l2_rx_desc_cnt[15]),     0,       0,       0,      0 },
        #endif

        /* The maximum page count is chosen to prevent us from having
         * more than 32767 pending entries at any one time. */
        { _OFFSET(l2_tx_bd_page_cnt[0]),   2,       2,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[1]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[2]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[3]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[4]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[5]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[6]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[7]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[8]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[9]),   1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[10]),  1,       1,       1,      127 },
        { _OFFSET(l2_tx_bd_page_cnt[11]),  1,       1,       1,      127 },

        { _OFFSET(l2_rx_bd_page_cnt[0]),   2,       2,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[1]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[2]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[3]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[4]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[5]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[6]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[7]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[8]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[9]),   1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[10]),  1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[11]),  1,       1,       1,      127 },
        #if 0
        { _OFFSET(l2_rx_bd_page_cnt[12]),  1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[13]),  1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[14]),  1,       1,       1,      127 },
        { _OFFSET(l2_rx_bd_page_cnt[15]),  1,       1,       1,      127 },
        #endif

        { _OFFSET(l4_tx_bd_page_cnt),      1,       1,       1,      255 },
        { _OFFSET(limit_l4_tx_bd_cnt),     0,       0,       0,      0 },
        { _OFFSET(l4_rx_bd_page_cnt),      1,       1,       1,      255 },
        { _OFFSET(limit_l4_rx_bd_cnt),     0,       0,       0,      0 },

        #ifndef EXCLUDE_KQE_SUPPORT
        #if INCLUDE_OFLD_SUPPORT
        { _OFFSET(kwq_page_cnt),           4,       2,       1,      255 },
        { _OFFSET(kcq_page_cnt),           32,      32,      1,      255 },
        { _OFFSET(kcq_history_size),       0x80,    0x80,    0,      0   },
        #else
        /* Kernel queues are used when RSS or TCP offload is enabled.
         * When RSS is enabled, the upper module should modify the
         * default settings for these parameters. */
        { _OFFSET(kwq_page_cnt),           0,       0,       0,      0 },
        { _OFFSET(kcq_page_cnt),           0,       0,       0,      0 },
        { _OFFSET(kcq_history_size),       0,       0,       0,      0 },
        #endif

        /* Connection kcqe/kwqe history. */
        { _OFFSET(con_kcqe_history_size),  0,       0,       0,      0 },
        { _OFFSET(con_kwqe_history_size),  0,       0,       0,      0 },
        #endif

        { _OFFSET(gen_bd_page_cnt),        2,       2,       1,      127 },
        { _OFFSET(max_gen_buf_cnt),        0x8000,  0x8000,  0,      0 },
        { _OFFSET(gen_buf_per_alloc),      0x4,    0x4,      0,      0 },

        { _OFFSET(copy_buffered_data),     0,       0,       0,      0 },
        { _OFFSET(rcv_buffer_offset),      0x38,    0x38,    0,      0 },
        { _OFFSET(enable_syn_rcvq),        0,       0,       0,      0 },

        { _OFFSET(hcopy_desc_cnt),         0,       0,       0,      0 },
        { _OFFSET(hcopy_bd_page_cnt),      2,       2,       1,      127 },
        { _OFFSET(buffered_kcqe_cnt),      0x80,    0x80,    0,      0 },

        { _OFFSET(deferred_kcqe_cnt),      0x100,   0x100,   0,      0 },

        { _OFFSET(test_mode),              0x60,    0x60,    0,      0 },
        { _OFFSET(ofld_cap),               0,       0,       0,      0 },
        { _OFFSET(wol_cap),                0,       0,       0,      0 },
        { _OFFSET(flow_ctrl_cap),          0,       0,       0,      0 },
        { _OFFSET(req_medium),             0,       0,       0,      0xfffff },
        { _OFFSET(selective_autoneg),      0,       0,       0,      0 },
        { _OFFSET(wire_speed),             1,       0,       0,      0 },
        { _OFFSET(phy_addr),               1,       0,       0,      0 },
        { _OFFSET(phy_int_mode),           2,       2,       0,      0 },
        { _OFFSET(link_chng_mode),         2,       2,       0,      0 },

        { _OFFSET(hc_timer_mode),          0,       0,       0,      0 },
        { _OFFSET(ind_comp_limit),         200,     100,     0,      0 },
        { _OFFSET(tx_quick_cons_trip_int), 3,       10,      0,      0 },
        { _OFFSET(tx_quick_cons_trip),     3,       30,      0,      0 },
        { _OFFSET(tx_ticks_int),           30,      10,      0,      0 },
        { _OFFSET(tx_ticks),               60,      200,     0,      0 },
        { _OFFSET(rx_quick_cons_trip_int), 1,       3,       0,      0 },
        { _OFFSET(rx_quick_cons_trip),     2,       1,       0,      0 },
        { _OFFSET(rx_ticks_int),           15,      5,       0,      0 },
        { _OFFSET(rx_ticks),               45,      1,       0,      0 },
        { _OFFSET(comp_prod_trip_int),     2,       3,       0,      0 },
        { _OFFSET(comp_prod_trip),         4,       1,       0,      0 },
        { _OFFSET(com_ticks_int),          64,      5,       0,      0 },
        { _OFFSET(com_ticks),              220,     1,       0,      0 },
        { _OFFSET(cmd_ticks_int),          64,      5,       0,      0 },
        { _OFFSET(cmd_ticks),              220,     1,       0,      0 },
        { _OFFSET(stats_ticks),            1000000, 1000000, 0,      0 },

        /* Xinan per-processor HC configuration. */
        { _OFFSET(psb_tx_cons_trip),       0x100010,0x100010,0,      0 },
        { _OFFSET(psb_tx_ticks),           0x100040,0x100040,0,      0 },
        { _OFFSET(psb_rx_cons_trip),       0x100010,0x100010,0,      0 },
        { _OFFSET(psb_rx_ticks),           0x80020, 0x80020, 0,      0 },
        { _OFFSET(psb_comp_prod_trip),     0x80008, 0x80008, 0,      0 },
        { _OFFSET(psb_com_ticks),          0x400040,0x400040,0,      0 },
        { _OFFSET(psb_cmd_ticks),          0x400040,0x400040,0,      0 },
        { _OFFSET(psb_period_ticks),       0,       0,       0,      0 },

        { _OFFSET(enable_fir),             1,       1,       0,      0 },
        { _OFFSET(num_rchans),             5,       5,       0,      0 },
        { _OFFSET(num_wchans),             3,       3,       0,      0 },

        /* One some system, with one_tdma disabled, we will get data
         * corruption.  Currently this looks like a chipset bug.  The
         * chip group will continue to look into this.  So for now, we
         * will enable one_tdma for all chip revisions. */
        { _OFFSET(one_tdma),               0,       0,       0,      0 },

        { _OFFSET(ping_pong_dma),          0,       0,       0,      0 },
        { _OFFSET(tmr_reload_value1),      0x6c627970, 0,    0,      0 },
        { _OFFSET(keep_vlan_tag),          0,       0,       0,      0 },

        { _OFFSET(enable_remote_phy),      0,       0,       0,      0 },
        { _OFFSET(rphy_req_medium),        0,       0,       0,      0 },
        { _OFFSET(rphy_flow_ctrl_cap),     0,       0,       0,      0 },
        { _OFFSET(rphy_selective_autoneg), 0,       0,       0,      0 },
        { _OFFSET(rphy_wire_speed),        1,       0,       0,      0 },

        { _OFFSET(bin_mq_mode),            0,       0,       0,      0 },
        { _OFFSET(validate_l4_data),       0,       0,       0,      0 },
        { _OFFSET(disable_pcie_nfr),       0,       0,       0,      0 },
        { _OFFSET(fw_flow_control),        0,       0,       0,      0 },
        { _OFFSET(fw_flow_control_wait),   0xffff,  0xffff,  0,      0xffff },
        { _OFFSET(ena_large_grc_timeout),  0,       0,       0,      0 },
        { _OFFSET(flow_control_reporting_mode),     0,       0,      0,      0 },
        { 0,                               0,       0,       0,      0 }
    };

    lm_status_t lm_status;
    param_entry_t *param;
    u32_t val;

    DbgMessage(pdev, INFORMi, "### lm_get_dev_info\n");

    /* Get PCI device and vendor id. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_vendor_id),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.vid = (u16_t) val;
    DbgMessage1(pdev, INFORMi, "vid 0x%x\n", pdev->hw_info.vid);

    pdev->hw_info.did = (u16_t) (val >> 16);
    DbgMessage1(pdev, INFORMi, "did 0x%x\n", pdev->hw_info.did);

    /* Get subsystem and subvendor id. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_subsystem_vendor_id),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.svid = (u16_t) val;
    DbgMessage1(pdev, INFORMi, "svid 0x%x\n", pdev->hw_info.svid);

    pdev->hw_info.ssid = (u16_t) (val >> 16);
    DbgMessage1(pdev, INFORMi, "ssid 0x%x\n", pdev->hw_info.ssid);

    /* Get IRQ, and interrupt pin. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_int_line),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.irq = (u8_t) val;
    DbgMessage1(pdev, INFORMi, "IRQ 0x%x\n", pdev->hw_info.irq);

    pdev->hw_info.int_pin = (u8_t) (val >> 8);
    DbgMessage1(pdev, INFORMi, "Int pin 0x%x\n", pdev->hw_info.int_pin);

    /* Get cache line size. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_cache_line_size),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.cache_line_size = (u8_t) val;
    DbgMessage1(pdev, INFORMi, "Cache line size 0x%x\n", (u8_t) val);

    pdev->hw_info.latency_timer = (u8_t) (val >> 8);
    DbgMessage1(pdev, INFORMi, "Latency timer 0x%x\n", (u8_t) (val >> 8));

    /* Get PCI revision id. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_class_code),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    pdev->hw_info.rev_id = (u8_t) val;
    DbgMessage1(pdev, INFORMi, "Revision id 0x%x\n", pdev->hw_info.rev_id);

    /* Get the base address. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_bar_1),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

#ifndef CONFIG_PPC64
    pdev->hw_info.mem_base.as_u32.low = val & 0xfffffff0;
#endif

    DbgMessage1(pdev, INFORMi, "Mem base low 0x%x\n", pdev->hw_info.mem_base.as_u32.low);

    val = 0;

    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_bar_2),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

#ifndef CONFIG_PPC64
    pdev->hw_info.mem_base.as_u32.high = val;
#endif

    DbgMessage1(pdev, INFORMi, "Mem base high 0x%x\n",
        pdev->hw_info.mem_base.as_u32.high);

    /* Enable PCI bus master.  This is supposed to be enabled by the
     * BIOS, however, BIOS on older systems may not set this bit. */
    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_command),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Error out if memory map is NOT enabled.  This could occur if the
     * BIOS is not able to reserve an address range for the device. */
    if(!(val & PCICFG_COMMAND_MEM_SPACE))
    {
        DbgBreakMsg("MEM_SPACE not enabled.\n");

        return LM_STATUS_FAILURE;
    }

    val |= PCICFG_COMMAND_BUS_MASTER;

    lm_status = mm_write_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_command),
        val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Configure byte swap and enable write to the reg_window registers. */
    val = PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
        PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP;
    lm_status = mm_write_pci(
        pdev,
        OFFSETOF(reg_space_t, pci_config.pcicfg_misc_config),
        val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Get the bar size at register 0x408 via PCI configuration indirect. */
    lm_status = mm_write_pci(
        pdev,
        OFFSETOF(pci_config_t, pcicfg_reg_window_address),
        OFFSETOF(reg_space_t, pci.pci_config_2));
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = mm_read_pci(
        pdev,
        OFFSETOF(pci_config_t, pcicfg_reg_window),
        &val);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    val &= PCI_CONFIG_2_BAR1_SIZE;
    if(val == PCI_CONFIG_2_BAR1_SIZE_DISABLED ||
        val > PCI_CONFIG_2_BAR1_SIZE_1G)
    {
        DbgBreakMsg("Invalid bar size.\n");

        return LM_STATUS_FAILURE;
    }

    pdev->hw_info.bar_size = 1 << (val+15);
    DbgMessage1(pdev, INFORM, "bar_size 0x%x\n", pdev->hw_info.bar_size);

    /* Map memory base to system address space. */
    pdev->vars.regview = (reg_space_t *) mm_map_io_base(
        pdev,
        pdev->hw_info.mem_base,
        pdev->hw_info.bar_size);
    if(pdev->vars.regview == NULL)
    {
        return LM_STATUS_FAILURE;
    }
    DbgMessage1(pdev, INFORMi, "Mapped base %p\n", pdev->vars.regview);

    #if DBG
    /* Make sure byte swapping is properly configured. */
    REG_RD(pdev, pci.pci_swap_diag0, &val);

    DbgBreakIf(val != 0x1020304);
    #endif

    /* Get the chip revision id and number. */
    REG_RD(pdev, misc.misc_id, &pdev->hw_info.chip_id);
    DbgMessage1(pdev, INFORMi, "chip id 0x%x\n", pdev->hw_info.chip_id);

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        pdev->hw_info.bus_mode = BUS_MODE_PCIE;
    }
    else
    {
        /* Get bus information. */
        REG_RD(pdev, pci_config.pcicfg_misc_status, &val);

        if(val & PCICFG_MISC_STATUS_32BIT_DET)
        {
            pdev->hw_info.bus_width = BUS_WIDTH_32_BIT;
            DbgMessage(pdev, INFORM, "32bit bus width.\n");
        }
        else
        {
            pdev->hw_info.bus_width = BUS_WIDTH_64_BIT;
            DbgMessage(pdev, INFORM, "64bit bus width.\n");
        }

        if(val & PCICFG_MISC_STATUS_PCIX_DET)
        {
            pdev->hw_info.bus_mode = BUS_MODE_PCIX;
            DbgMessage(pdev, INFORM, "PCIX bus detected.\n");

            REG_RD(pdev, pci_config.pcicfg_pci_clock_control_bits, &val);
            switch(val & PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET)
            {
            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_133MHZ:
                pdev->hw_info.bus_speed = BUS_SPEED_133_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 133Mhz.\n");
                break;

            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_95MHZ:
                pdev->hw_info.bus_speed = BUS_SPEED_100_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 100Mhz.\n");
                break;

            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_66MHZ:
            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_80MHZ:
                pdev->hw_info.bus_speed = BUS_SPEED_66_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 66Mhz.\n");
                break;

            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_48MHZ:
            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_55MHZ:
                pdev->hw_info.bus_speed = BUS_SPEED_50_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 50Mhz.\n");
                break;

            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET:
            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_32MHZ:
            case PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_38MHZ:
            default:
                pdev->hw_info.bus_speed = BUS_SPEED_33_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 33Mhz.\n");
                break;
            }
        }
        else
        {
            pdev->hw_info.bus_mode = BUS_MODE_PCI;
            DbgMessage(pdev, INFORM, "Conventional PCI bus detected.\n");

            if(val & PCICFG_MISC_STATUS_M66EN)
            {
                pdev->hw_info.bus_speed = BUS_SPEED_66_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 66Mhz.\n");
            }
            else
            {
                pdev->hw_info.bus_speed = BUS_SPEED_33_MHZ;
                DbgMessage(pdev, INFORM, "Bus speed is 33Mhz.\n");
            }
        }
    }

    if(CHIP_ID(pdev) == CHIP_ID_5706_A0 || CHIP_ID(pdev) == CHIP_ID_5706_A1)
    {
        REG_RD_OFFSET(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_command),
            &val);

        /* 5706A0 may falsely detect SERR and PERR. */
        if(CHIP_ID(pdev) == CHIP_ID_5706_A0)
        {
            val &= ~(PCICFG_COMMAND_SERR_ENA | PCICFG_COMMAND_PERR_ENA);
        }

        /* 5706A1 PCI 64-bit. */
        else if(pdev->hw_info.bus_mode == BUS_MODE_PCI &&
            pdev->hw_info.bus_width == BUS_WIDTH_64_BIT)
        {
            /* E4_5706A1_577: PERR IS INCORRECTLY GENERATED IN PCI 64-BIT.
               Description: If the data on the upper AD and CBE busses
                  do not match the parity of PAR64 during a 32-bit target
                  access, a parity error is incorrectly generated. This
                  happens only after a 64-bit master DMA operation has been
                  done by the chip.
               Scope: All PCI 64-bit systems.
               Impact: Ability to indicate a real parity error is lost.
               Workaround: Driver needs to clear PERR_EN. */
            val &= ~PCICFG_COMMAND_PERR_ENA;
        }

        REG_WR_OFFSET(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_command),
            val);
    }
    else if(CHIP_ID(pdev) == CHIP_ID_5708_A0)
    {
        /* 5708A0 errata. */
        REG_RD_OFFSET(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_command),
            &val);

        val &= ~(PCICFG_COMMAND_SERR_ENA | PCICFG_COMMAND_PERR_ENA);

        REG_WR_OFFSET(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_command),
            val);
    }

    /* Get the EPB info. */
    if(CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        REG_RD_IND(pdev, 0x240000+0x18, &val);
        pdev->hw_info.pcie_bus_num = (u8_t) val;

        REG_RD_IND(pdev, 0x240000+0x6c, &val);
        pdev->hw_info.pcie_max_width = (u8_t) ((val & 0x3f0) >> 4);

        switch(val & 0xf)
        {
            case 1:
                pdev->hw_info.pcie_max_speed = PCIE_SPEED_2_5_G;
                break;

            default:
                pdev->hw_info.pcie_max_speed = 0;
                break;
        }

        REG_RD_IND(pdev, 0x240000+0x70, &val);
        pdev->hw_info.pcie_width = (u8_t) ((val & 0x3f00000) >> 20);

        switch(val & 0xf0000)
        {
            case 0x10000:
                pdev->hw_info.pcie_speed = PCIE_SPEED_2_5_G;
                break;

            default:
                pdev->hw_info.pcie_speed = 0;
                break;
        }
    }
    else if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, pci_config.pcicfg_link_capability, &val);
        pdev->hw_info.pcie_max_width =
            (u8_t) ((val & PCICFG_LINK_CAPABILITY_MAX_LINK_WIDTH) >> 4);
        switch (val & PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED)
        {
            case PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED_5:
                pdev->hw_info.pcie_max_speed = PCIE_SPEED_5_G;
                break;
            case PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED_2_5:
                pdev->hw_info.pcie_max_speed = PCIE_SPEED_2_5_G;
                break;
            default:
                pdev->hw_info.pcie_max_speed = 0;
                break;
        }

        REG_RD(pdev, pci_config.pcicfg_link_status, &val);
        pdev->hw_info.pcie_width =
            (u8_t) ((val & PCICFG_LINK_STATUS_NEG_LINK_WIDTH) >> 4);
        switch (val & PCICFG_LINK_STATUS_SPEED)
        {
            case PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED_5:
                pdev->hw_info.pcie_speed = PCIE_SPEED_5_G;
                break;
            case PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED_2_5:
                pdev->hw_info.pcie_speed = PCIE_SPEED_2_5_G;
                break;
            default:
                pdev->hw_info.pcie_speed = 0;
                break;
        }

        REG_RD_IND(pdev, OFFSETOF(reg_space_t, mcp.mcp_toe_id), &val);
        if(val & MCP_TOE_ID_FUNCTION_ID)
        {
            pdev->hw_info.mac_id = 1;
        }
    }

    /* Get firmware share memory base address. */
    REG_RD_IND(
        pdev,
        MCP_SCRATCHPAD_START + OFFSETOF(shm_hdr_t, shm_hdr_signature),
        &val);
    if((val & SHM_ADDR_SIGN_MASK) == SHM_ADDR_SIGNATURE)
    {
        REG_RD_IND(
            pdev,
            MCP_SCRATCHPAD_START +
                OFFSETOF(shm_hdr_t, shm_addr[pdev->hw_info.mac_id]),
            &pdev->hw_info.shmem_base);
    }
    else
    {
        /* Pre v1.3.2 bootcode. */
        pdev->hw_info.shmem_base = HOST_VIEW_SHMEM_BASE;
    }

    /* Get the hw config word. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, dev_info.shared_hw_config.config),
        &val);
    pdev->hw_info.nvm_hw_config = val;

    get_max_conns(
        pdev,
        &pdev->hw_info.max_toe_conn,
        &pdev->hw_info.max_iscsi_conn,
        &pdev->hw_info.max_iscsi_pending_tasks);

    /* Get the permanent MAC address. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, dev_info.port_hw_config.mac_upper),
        &val);
    pdev->hw_info.mac_addr[0] = (u8_t) (val >> 8);
    pdev->hw_info.mac_addr[1] = (u8_t) val;

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, dev_info.port_hw_config.mac_lower),
        &val);

    pdev->hw_info.mac_addr[2] = (u8_t) (val >> 24);
    pdev->hw_info.mac_addr[3] = (u8_t) (val >> 16);
    pdev->hw_info.mac_addr[4] = (u8_t) (val >> 8);
    pdev->hw_info.mac_addr[5] = (u8_t) val;

    /* Get iSCSI MAC address. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(
                shmem_region_t,
                dev_info.port_hw_config.iscsi_mac_upper),
         &val);
    pdev->hw_info.iscsi_mac_addr[0] = (u8_t) (val >> 8);
    pdev->hw_info.iscsi_mac_addr[1] = (u8_t) val;

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(
                shmem_region_t,
                dev_info.port_hw_config.iscsi_mac_lower),
        &val);
    pdev->hw_info.iscsi_mac_addr[2] = (u8_t) (val >> 24);
    pdev->hw_info.iscsi_mac_addr[3] = (u8_t) (val >> 16);
    pdev->hw_info.iscsi_mac_addr[4] = (u8_t) (val >> 8);
    pdev->hw_info.iscsi_mac_addr[5] = (u8_t) val;

    DbgMessage6(pdev, INFORM, "mac addr: %02x %02x %02x %02x %02x %02x\n",
        pdev->hw_info.mac_addr[0],
        pdev->hw_info.mac_addr[1],
        pdev->hw_info.mac_addr[2],
        pdev->hw_info.mac_addr[3],
        pdev->hw_info.mac_addr[4],
        pdev->hw_info.mac_addr[5]);

    DbgBreakIf(LM_DRIVER_MAJOR_VER > 255);
    DbgBreakIf(LM_DRIVER_MINOR_VER > 255);
    DbgBreakIf(LM_DRIVER_REL_NUM > 255);
    DbgBreakIf(LM_DRIVER_FIX_NUM > 255);

    pdev->ver_num =
        (LM_DRIVER_MAJOR_VER << 24) |
        (LM_DRIVER_MINOR_VER << 16) |
        (LM_DRIVER_REL_NUM << 8)    |
        LM_DRIVER_FIX_NUM;

    (void) build_ver_string(
        (char *)pdev->ver_str,
        sizeof(pdev->ver_str),
        LM_DRIVER_MAJOR_VER,
        LM_DRIVER_MINOR_VER,
        LM_DRIVER_REL_NUM,
        LM_DRIVER_FIX_NUM);

    pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0];
    pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1];
    pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2];
    pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3];
    pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4];
    pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5];

    /* Initialize the default parameters. */
    param = param_list;
    while(param->offset)
    {
        if(CHIP_REV(pdev) == CHIP_REV_FPGA || CHIP_REV(pdev) == CHIP_REV_IKOS)
        {
            SET_PARAM_VAL(pdev, param, param->fpga_ikos_default);
        }
        else
        {
            SET_PARAM_VAL(pdev, param, param->asic_default);
        }

        param++;
    }

    if(CHIP_REV(pdev) == CHIP_REV_FPGA || CHIP_REV(pdev) == CHIP_REV_IKOS)
    {
        pdev->params.test_mode |= TEST_MODE_INIT_GEN_BUF_DATA;
        pdev->params.test_mode |= TEST_MODE_SAVE_DUMMY_DMA_DATA;
        pdev->params.test_mode |= TEST_MODE_IGNORE_SHMEM_SIGNATURE;
        pdev->params.test_mode |= TEST_MODE_DRIVER_PULSE_ALWAYS_ALIVE;
    }

    /* Some chipsets are not capabable of handling multiple
     * read requests.  Currently we will get data corrupt on
     * Intel 840/860 chipset when one_tdma is not enabled. */
    if(pdev->hw_info.bus_mode == BUS_MODE_PCI)
    {
        if((CHIP_NUM(pdev)==CHIP_NUM_5706 || CHIP_NUM(pdev)==CHIP_NUM_5708) &&
            (CHIP_REV(pdev)==CHIP_REV_FPGA || CHIP_REV(pdev)==CHIP_REV_IKOS))
        {
            pdev->params.ping_pong_dma = FALSE;
        }
        else
        {
            pdev->params.ping_pong_dma = TRUE;
        }
    }
    else
    {
        pdev->params.ping_pong_dma = FALSE;
    }

    /* Get the pre-emphasis. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, dev_info.port_hw_config.config),
        &pdev->params.serdes_pre_emphasis);
    pdev->params.serdes_pre_emphasis &= PORT_HW_CFG_SERDES_TXCTL3_MASK;

    /* This should be fixed in A1. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A0)
    {
        if(pdev->hw_info.bus_mode == BUS_MODE_PCIX &&
            pdev->hw_info.bus_speed == BUS_SPEED_133_MHZ)
        {
            pdev->params.num_rchans = 1;
        }
    }

    #if defined(DBG) && !defined(EXCLUDE_KQE_SUPPORT)
    pdev->params.con_kcqe_history_size = 256;
    pdev->params.con_kwqe_history_size = 256;
    #endif

    if(CHIP_NUM(pdev) == CHIP_NUM_5708 || CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        if(lm_get_medium(pdev) == LM_MEDIUM_TYPE_FIBER)
        {
            pdev->params.phy_addr = 2;
        }
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        pdev->params.bin_mq_mode = TRUE;
    }

    DbgBreakIf(NUM_RX_CHAIN != NUM_TX_CHAIN);

    pdev->rx_info.num_rxq = NUM_RX_CHAIN;
    pdev->tx_info.num_txq = NUM_TX_CHAIN;
    pdev->tx_info.cu_idx = TX_CHAIN_IDX1;

    /* see if remote phy is enabled. */
    if(CHIP_REV(pdev) != CHIP_REV_IKOS)
    {
        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t,
                    dev_info.port_feature_config.config),
            &val);
        if(val & PORT_FEATURE_RPHY_ENABLED)
        {
            pdev->params.enable_remote_phy = 1;
        }
    }

    if (CHIP_NUM(pdev) == CHIP_NUM_5706 ||
        CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        // Due to slower speed of RV2P in Teton, we need to limit max
        // number of BD per each end bit. Otherwise, Appscan in RV2P
        // would spend excessive time scanning for end bit.
        pdev->params.limit_l4_rx_bd_cnt = 110;
    }

    /* Override the defaults with user configurations. */
    lm_status = mm_get_user_config(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Make sure share memory is initialized by the firmware.  If not
     * fail initialization.  The check here is a little late as we
     * have already read some share memory info above.  This is ok. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, dev_info.signature),
        &val);
    if((val & DEV_INFO_SIGNATURE_MASK) != DEV_INFO_SIGNATURE)
    {
        if(!(pdev->params.test_mode & TEST_MODE_IGNORE_SHMEM_SIGNATURE))
        {
            DbgBreakMsg("Shmem signature not present.\n");

            return LM_STATUS_BAD_SIGNATURE;
        }

        pdev->hw_info.mac_addr[0] = 0x00;
        pdev->hw_info.mac_addr[1] = 0x10;
        pdev->hw_info.mac_addr[2] = 0x18;
        pdev->hw_info.mac_addr[3] = 0xff;
        pdev->hw_info.mac_addr[4] = 0xff;
        pdev->hw_info.mac_addr[5] = 0xff;

        pdev->hw_info.iscsi_mac_addr[0] = 0x00;
        pdev->hw_info.iscsi_mac_addr[1] = 0x10;
        pdev->hw_info.iscsi_mac_addr[2] = 0x18;
        pdev->hw_info.iscsi_mac_addr[3] = 0xff;
        pdev->hw_info.iscsi_mac_addr[4] = 0xff;
        pdev->hw_info.iscsi_mac_addr[5] = 0xfe;
    }

    /* Make sure the parameter values are within range. */
    param = param_list;
    while(param->offset)
    {
        if(param->min != 0 || param->max != 0)
        {
            if(PARAM_VAL(pdev, param) < param->min ||
                PARAM_VAL(pdev, param) > param->max)
            {
                if(CHIP_REV(pdev) == CHIP_REV_FPGA ||
                    CHIP_REV(pdev) == CHIP_REV_IKOS)
                {
                    SET_PARAM_VAL(pdev, param, param->fpga_ikos_default);
                }
                else
                {
                    SET_PARAM_VAL(pdev, param, param->asic_default);
                }
            }
        }

        param++;
    }

    /* params.mtu read from the registry does not include the MAC header
     * size.  We need to add the header here. */
    /*
     * get_vbd_params does this aleady
     * pdev->params.mtu += ETHERNET_PACKET_HEADER_SIZE;
     */

    #ifndef EXCLUDE_KQE_SUPPORT
    /* The size of the kcq histroy.  This is the number entries that will
     * not be over written by the chip. */
    if(pdev->params.kcq_history_size > (LM_PAGE_SIZE/sizeof(kcqe_t)) *
        pdev->params.kcq_page_cnt - 1)
    {
        pdev->params.kcq_history_size = ((LM_PAGE_SIZE/sizeof(kcqe_t)) *
            pdev->params.kcq_page_cnt) / 2;
    }
    #endif

    /* XXX: Exception for Xinan, need a permanent fix. */
    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        pdev->params.rcv_buffer_offset = 0;
    }

    /* Check for a valid mac address. */
    if((pdev->params.mac_addr[0] == 0 &&
        pdev->params.mac_addr[1] == 0 &&
        pdev->params.mac_addr[2] == 0 &&
        pdev->params.mac_addr[3] == 0 &&
        pdev->params.mac_addr[4] == 0 &&
        pdev->params.mac_addr[5] == 0) || (pdev->params.mac_addr[0] & 1))
    {
        DbgMessage(pdev, WARN, "invalid LAA.\n");

        pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0];
        pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1];
        pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2];
        pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3];
        pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4];
        pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5];
    }

    /* There is a bug in HC that will cause it to stop updating the
     * status block.  This has been shown on some system with L4 traffic
     * goinging.  To workaround this, the trip points and interrupt trip
     * points must be the same and the statistics DMA must be disabled. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A0)
    {
        pdev->params.tx_quick_cons_trip_int = pdev->params.tx_quick_cons_trip;
        pdev->params.tx_ticks_int = pdev->params.tx_ticks;
        pdev->params.rx_quick_cons_trip_int = pdev->params.rx_quick_cons_trip;
        pdev->params.rx_ticks_int = pdev->params.rx_ticks;
        pdev->params.comp_prod_trip_int = pdev->params.comp_prod_trip;
        pdev->params.com_ticks_int = pdev->params.com_ticks;
        pdev->params.cmd_ticks_int = pdev->params.cmd_ticks;
        pdev->params.stats_ticks = 0;
    }

    /* enable_syn_rcvd will direct all tcp segments with syn bit to rxq 1. */
    if(pdev->params.enable_syn_rcvq &&
        NUM_RX_CHAIN > 1 &&
        pdev->params.l2_rx_desc_cnt[1] == 0)
    {
        pdev->params.l2_rx_desc_cnt[1] = 60;
    }

    /* Timer mode is broken is 5706_A0 and 5706_A1. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A0 || CHIP_ID(pdev) == CHIP_ID_5706_A1)
    {
        pdev->params.hc_timer_mode = HC_COLLECT_MODE;
    }

    /* Get the current fw_wr_seq. */
    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base + OFFSETOF(shmem_region_t, drv_fw_mb.fw_mb),
        &val);
    pdev->vars.fw_wr_seq = val & DRV_MSG_SEQ;

    /* see if firmware is remote phy capable. */
    if(pdev->params.enable_remote_phy)
    {
        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, drv_fw_cap_mb.fw_cap_mb),
            &val);
        if((val & CAPABILITY_SIGNATURE_MASK) != FW_CAP_SIGNATURE ||
            (val & FW_CAP_REMOTE_PHY_CAPABLE) == 0)
        {
            pdev->params.enable_remote_phy = 0;
        }
    }

    return LM_STATUS_SUCCESS;
} /* lm_get_dev_info */



#ifndef EXCLUDE_KQE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_kwq_resc(
    lm_device_t *pdev)
{
    u32_t mem_size;

    if(pdev->params.kwq_page_cnt == 0)
    {
        return LM_STATUS_SUCCESS;
    }

    /* Allocate memory for the page table which does not need to be
     * page aligned.  However the size must be multiple of page size.
     *
     * When initialized, the page table will point to the pages
     * used for the kernel work queue. */
    mem_size = pdev->params.kwq_page_cnt * sizeof(lm_address_t);
    mem_size = (mem_size + LM_PAGE_MASK) & ~LM_PAGE_MASK;

    pdev->kq_info.kwq_pgtbl_virt = mm_alloc_phys_mem(
        pdev,
        mem_size,
        &pdev->kq_info.kwq_pgtbl_phy,
        PHYS_MEM_TYPE_NONCACHED,
        NULL);
    if(pdev->kq_info.kwq_pgtbl_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(pdev->kq_info.kwq_pgtbl_phy.as_u32.low & CACHE_LINE_SIZE_MASK);

    /* Allocate memory for the kernel work queue.  Here we allocate
     * a physically continuous block of memory and then initialize the
     * page table to pointer to the pages in this block.
     *
     * The kernel work queue is used by the driver similiar to a
     * circular ring.
     *
     * The memory block must be page aligned. */
    mem_size = LM_PAGE_SIZE * pdev->params.kwq_page_cnt;
    pdev->kq_info.kwq_virt = (kwqe_t *) mm_alloc_phys_mem(
        pdev,
        mem_size,
        &pdev->kq_info.kwq_phy,
        PHYS_MEM_TYPE_NONCACHED,
        NULL);
    if(pdev->kq_info.kwq_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(pdev->kq_info.kwq_phy.as_u32.low & CACHE_LINE_SIZE_MASK);
    DbgBreakIf(((u8_t *) pdev->kq_info.kwq_virt - (u8_t *) 0) & LM_PAGE_MASK);

    return LM_STATUS_SUCCESS;
} /* init_kwq_resc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_kcq_resc(
    lm_device_t *pdev)
{

    u32_t mem_size;

    if(pdev->params.kcq_page_cnt == 0)
    {
        return LM_STATUS_SUCCESS;
    }

    /* Allocate memory for the page table which does not need to be
     * page aligned.  However the size must be multiple of page size.
     *
     * When initialized, the page table will point to the pages
     * used for the kernel completion queue. */
    mem_size = pdev->params.kcq_page_cnt * sizeof(lm_address_t);
    mem_size = (mem_size + LM_PAGE_MASK) & ~LM_PAGE_MASK;

    pdev->kq_info.kcq_pgtbl_virt = mm_alloc_phys_mem(
        pdev,
        mem_size,
        &pdev->kq_info.kcq_pgtbl_phy,
        PHYS_MEM_TYPE_NONCACHED,
        NULL);
    if(pdev->kq_info.kcq_pgtbl_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(pdev->kq_info.kcq_pgtbl_phy.as_u32.low & CACHE_LINE_SIZE_MASK);

    /* Allocate memory for the kernel completion queue.  Here we allocate
     * a physically continuous block of memory and then initialize the
     * page table to pointer to the pages in this block.
     *
     * The kernel completion queue is used by the driver similiar to a
     * circular ring.
     *
     * The memory block must be page aligned. */
    mem_size = LM_PAGE_SIZE * pdev->params.kcq_page_cnt;

    pdev->kq_info.kcq_virt = (kcqe_t *) mm_alloc_phys_mem(
        pdev,
        mem_size,
        &pdev->kq_info.kcq_phy,
        PHYS_MEM_TYPE_NONCACHED,
        NULL);
    if(pdev->kq_info.kcq_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(pdev->kq_info.kcq_phy.as_u32.low & CACHE_LINE_SIZE_MASK);
    DbgBreakIf(((u8_t *) pdev->kq_info.kcq_virt - (u8_t *) 0) & LM_PAGE_MASK);

    return LM_STATUS_SUCCESS;
} /* init_kcq_resc */
#endif /* EXCLUDE_KQE_SUPPORT */



#if INCLUDE_OFLD_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_ofld_resc(
    lm_device_t *pdev)
{
    lm_offload_info_t *ofld;
    u32_t mem_size;
    u32_t idx;

    ofld = &pdev->ofld;
    ofld->pdev = pdev;
    ofld->pg_cid_hnd_info.max_pending_pg_oflds = 16;
    ofld->pg_cid_hnd_info.pending_pg_ofld_cnt = 0;

    s_list_init(&ofld->active_req_list, NULL, NULL, 0);
    s_list_init(&ofld->upload_req_list, NULL, NULL, 0);

    for(idx = 0; idx < STATE_BLOCK_CNT; idx++)
    {
        d_list_init(&ofld->state_blks[idx].tcp_list, NULL, NULL, 0);
        d_list_init(&ofld->state_blks[idx].path_list, NULL, NULL, 0);
        d_list_init(&ofld->state_blks[idx].neigh_list, NULL, NULL, 0);

        ofld->state_blks[idx].max_conn = 0xffffffff;

        ofld->state_blks[idx].state_block_idx = idx;
        ofld->state_blks[idx].ofld = ofld;

        ofld->state_blks[idx].params.ticks_per_second = 100;
        ofld->state_blks[idx].params.ack_frequency = 2;
        ofld->state_blks[idx].params.delayed_ack_ticks = 20;
        ofld->state_blks[idx].params.max_retx = 10;
        ofld->state_blks[idx].params.doubt_reachability_retx = 8;
        ofld->state_blks[idx].params.sws_prevention_ticks = 10;
        ofld->state_blks[idx].params.dup_ack_threshold = 3;
        ofld->state_blks[idx].params.push_ticks = 20;
        ofld->state_blks[idx].params.nce_stale_ticks = 20;
        ofld->state_blks[idx].params.starting_ip_id = 0x8000;
    }

    /* Allocate memory for the generic buffer chain. */
    mem_size = LM_PAGE_SIZE * pdev->params.gen_bd_page_cnt;
    ofld->gen_chain.bd_chain_virt = (rx_bd_t *) mm_alloc_phys_mem(
        pdev,
        mem_size,
        &ofld->gen_chain.bd_chain_phy,
        PHYS_MEM_TYPE_UNSPECIFIED,
        NULL);
    if(ofld->gen_chain.bd_chain_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(ofld->gen_chain.bd_chain_phy.as_u32.low & CACHE_LINE_SIZE_MASK);

    ofld->gen_chain.cid_addr = GET_CID_ADDR(GEN_CHAIN_CID);

    s_list_init(&ofld->gen_chain.block_list, NULL, NULL, 0);
    s_list_init(&ofld->gen_chain.free_gen_buf_list, NULL, NULL, 0);
    s_list_init(&ofld->gen_chain.active_gen_buf_list, NULL, NULL, 0);

    /* Allocate memory for the hcopy chain. */
    if(pdev->params.hcopy_desc_cnt)
    {
        mem_size = LM_PAGE_SIZE * pdev->params.hcopy_bd_page_cnt;
        ofld->hcopy_chain.bd_chain_virt =(tx_bd_t *) mm_alloc_phys_mem(
            pdev,
            mem_size,
            &ofld->hcopy_chain.bd_chain_phy,
            PHYS_MEM_TYPE_UNSPECIFIED,
            NULL);
        if(ofld->hcopy_chain.bd_chain_virt == NULL)
        {
            return LM_STATUS_RESOURCE;
        }

        DbgBreakIf(ofld->hcopy_chain.bd_chain_phy.as_u32.low &
            CACHE_LINE_SIZE_MASK);

        ofld->hcopy_chain.cid_addr = GET_CID_ADDR(HCOPY_CID);
        ofld->hcopy_chain.hw_con_idx_ptr =
            &pdev->vars.status_virt->deflt.status_rx_quick_consumer_index15;

        s_list_init(&ofld->hcopy_chain.pending_descq, NULL, NULL, 0);
        s_list_init(&ofld->hcopy_chain.active_descq, NULL, NULL, 0);
    }

    ofld->cid_to_state = (lm_state_header_t **) mm_alloc_mem(
        pdev,
        sizeof(lm_state_header_t *) * MAX_CID,
        NULL);
    if(ofld->cid_to_state == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    return LM_STATUS_SUCCESS;
} /* init_ofld_resc */
#endif /* INCLUDE_OFLD_SUPPORT */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC volatile u16_t *
sblk_tx_con_idx_ptr(
    lm_device_t *pdev,
    lm_tx_chain_t *txq)
{
    volatile status_blk_combined_t *sblk;
    volatile u16_t *idx_ptr;

    sblk = pdev->vars.status_virt;

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        switch(txq->idx)
        {
            case TX_CHAIN_IDX0:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index0;
                break;

            case TX_CHAIN_IDX1:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index1;
                break;

            case TX_CHAIN_IDX2:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index2;
                break;

            case TX_CHAIN_IDX3:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index3;
                break;

            default:
                idx_ptr = NULL;

                DbgBreakIf(txq->idx != pdev->tx_info.cu_idx);

                if(txq->idx == pdev->tx_info.cu_idx)
                {
                    idx_ptr = &sblk->deflt.status_rx_quick_consumer_index14;
                }
                break;
        }
    }
    else
    {
        switch(txq->idx)
        {
            case TX_CHAIN_IDX0:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index0;
                break;

            case TX_CHAIN_IDX1:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index1;
                break;

            case TX_CHAIN_IDX2:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index2;
                break;

            case TX_CHAIN_IDX3:
                idx_ptr = &sblk->deflt.status_tx_quick_consumer_index3;
                break;

            case TX_CHAIN_IDX4:
                idx_ptr = &sblk->proc[0].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX5:
                idx_ptr = &sblk->proc[1].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX6:
                idx_ptr = &sblk->proc[2].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX7:
                idx_ptr = &sblk->proc[3].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX8:
                idx_ptr = &sblk->proc[4].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX9:
                idx_ptr = &sblk->proc[5].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX10:
                idx_ptr = &sblk->proc[6].status_pcpu_tx_quick_consumer_index;
                break;

            case TX_CHAIN_IDX11:
                idx_ptr = &sblk->proc[7].status_pcpu_tx_quick_consumer_index;
                break;

            default:
                DbgBreakMsg("invalid xinan tx index.\n");
                idx_ptr = NULL;
                break;
        }
    }

    return idx_ptr;
} /* sblk_tx_con_idx_ptr */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_l2tx_resc(
    lm_device_t *pdev)
{
    lm_tx_chain_t *txq;
    u32_t bd_page_cnt;
    u32_t mem_size;
    u32_t idx;
    u32_t num_tx_chains;

#if defined(LM_NON_LEGACY_MODE_SUPPORT)
    num_tx_chains = MAX_TX_CHAIN;
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        num_tx_chains = pdev->tx_info.num_txq;
    }
#else
    DbgBreakIf(pdev->tx_info.num_txq > MAX_TX_CHAIN);
    for(idx = pdev->tx_info.num_txq; idx < MAX_TX_CHAIN; idx++)
    {
        pdev->params.l2_tx_bd_page_cnt[idx] = 0;
    }
    num_tx_chains = pdev->tx_info.num_txq;
#endif
    for(idx = 0; idx < num_tx_chains; idx++)
    {
        txq = &pdev->tx_info.chain[idx];
        txq->idx = idx;
        txq->cid_addr = GET_CID_ADDR(L2TX_CID_BASE + 2 * txq->idx);

        s_list_init(&txq->active_descq, NULL, NULL, 0);

        if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
        {
            DbgBreakIf(idx > 4);

            if(txq->idx == pdev->tx_info.cu_idx && txq->idx != TX_CHAIN_IDX1)
            {
                DbgBreakIf(idx != 4);
                txq->cid_addr = GET_CID_ADDR(30);
            }
        }
        else if(txq->idx >= 4)
        {
            DbgBreakIf(idx > 11);

            /* Xinan has to use tx1 for catchup because catchup2 uses
             * status_rx_quick_consumer_index14 for completion.  This
             * status block index is not available on Xinan. */
            DbgBreakIf(pdev->tx_info.cu_idx != TX_CHAIN_IDX1);

            if(txq->idx >= 4)
            {
                txq->cid_addr = GET_CID_ADDR(L2TX_TSS_CID_BASE + txq->idx - 4);
            }
        }

        bd_page_cnt = pdev->params.l2_tx_bd_page_cnt[txq->idx];
        if(bd_page_cnt)
        {
            mem_size = LM_PAGE_SIZE * bd_page_cnt;

            txq->bd_chain_virt = (tx_bd_t *) mm_alloc_phys_mem(
                pdev,
                mem_size,
                &txq->bd_chain_phy,
                PHYS_MEM_TYPE_NONCACHED,
                NULL);
            if(txq->bd_chain_virt == NULL)
            {
                return LM_STATUS_RESOURCE;
            }

            DbgBreakIf(txq->bd_chain_phy.as_u32.low & CACHE_LINE_SIZE_MASK);
        }

        txq->hw_con_idx_ptr = sblk_tx_con_idx_ptr(pdev, txq);
    }

    return LM_STATUS_SUCCESS;
} /* init_l2tx_resc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC volatile u16_t *
sblk_rx_con_idx_ptr(
    lm_device_t *pdev,
    lm_rx_chain_t *rxq)
{
    volatile status_blk_combined_t *sblk;
    volatile u16_t *idx_ptr;

    sblk = pdev->vars.status_virt;

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        switch(rxq->idx)
        {
            case RX_CHAIN_IDX0:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index0;
                break;

            case RX_CHAIN_IDX1:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index1;
                break;

            case RX_CHAIN_IDX2:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index2;
                break;

            case RX_CHAIN_IDX3:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index3;
                break;

            case RX_CHAIN_IDX4:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index4;
                break;

            case RX_CHAIN_IDX5:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index5;
                break;

            case RX_CHAIN_IDX6:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index6;
                break;

            case RX_CHAIN_IDX7:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index7;
                break;

            case RX_CHAIN_IDX8:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index8;
                break;

            case RX_CHAIN_IDX9:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index9;
                break;

            case RX_CHAIN_IDX10:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index10;
                break;

            case RX_CHAIN_IDX11:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index11;
                break;

            case RX_CHAIN_IDX12:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index12;
                break;

            case RX_CHAIN_IDX13:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index13;
                break;

            case RX_CHAIN_IDX14:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index14;
                break;

            case RX_CHAIN_IDX15:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index15;
                break;

            default:
                DbgBreakMsg("invalid teton rx index.\n");
                idx_ptr = NULL;
                break;
        }
    }
    else
    {
        switch(rxq->idx)
        {
            case RX_CHAIN_IDX0:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index0;
                break;

            case RX_CHAIN_IDX1:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index1;
                break;

            case RX_CHAIN_IDX2:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index2;
                break;

            case RX_CHAIN_IDX3:
                idx_ptr = &sblk->deflt.status_rx_quick_consumer_index3;
                break;

            case RX_CHAIN_IDX4:
                idx_ptr = &sblk->proc[0].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX5:
                idx_ptr = &sblk->proc[1].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX6:
                idx_ptr = &sblk->proc[2].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX7:
                idx_ptr = &sblk->proc[3].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX8:
                idx_ptr = &sblk->proc[4].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX9:
                idx_ptr = &sblk->proc[5].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX10:
                idx_ptr = &sblk->proc[6].status_pcpu_rx_quick_consumer_index;
                break;

            case RX_CHAIN_IDX11:
                idx_ptr = &sblk->proc[7].status_pcpu_rx_quick_consumer_index;
                break;

            default:
                DbgBreakMsg("invalid xinan rx index.\n");
                idx_ptr = NULL;
                break;
        }
    }

    return idx_ptr;
} /* sblk_rx_con_idx_ptr */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
alloc_l2rx_desc(
    lm_device_t *pdev,
    lm_rx_chain_t *rxq)
{
    u32_t bd_page_cnt;
    lm_packet_t *pkt;
    u32_t desc_size;
    u32_t desc_cnt;
    u8_t *mem_virt;
    u32_t mem_size;
    u32_t idx;

    bd_page_cnt = pdev->params.l2_rx_bd_page_cnt[rxq->idx];
    desc_cnt = pdev->params.l2_rx_desc_cnt[rxq->idx];

    if(bd_page_cnt == 0 || desc_cnt == 0)
    {
        pdev->params.l2_rx_bd_page_cnt[rxq->idx] = 0;
        pdev->params.l2_rx_desc_cnt[rxq->idx] = 0;

        return LM_STATUS_SUCCESS;
    }

    mem_size = LM_PAGE_SIZE * bd_page_cnt;

    rxq->bd_chain_virt = (rx_bd_t *) mm_alloc_phys_mem(
        pdev,
        mem_size,
        &rxq->bd_chain_phy,
        PHYS_MEM_TYPE_NONCACHED,
        NULL);
    if(rxq->bd_chain_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(rxq->bd_chain_phy.as_u32.low & CACHE_LINE_SIZE_MASK);

#ifndef LM_NON_LEGACY_MODE_SUPPORT
    desc_size = mm_desc_size(pdev, DESC_TYPE_L2RX_PACKET) + SIZEOF_SIG;
    mem_size = desc_size * desc_cnt;

    mem_virt = (u8_t *) mm_alloc_mem(pdev, mem_size, NULL);
    if(mem_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    for(idx = 0; idx < desc_cnt; idx++)
    {
        pkt = (lm_packet_t *) (mem_virt + SIZEOF_SIG);
        mem_virt += desc_size;
        mem_size -= desc_size;

        SIG(pkt) = L2PACKET_RX_SIG;
        // full packet needs to hold mtu + 4-byte CRC32
        pkt->u1.rx.buf_size = pdev->params.mtu + 4;
        pkt->u1.rx.buf_size += L2RX_FRAME_HDR_LEN;
        pkt->u1.rx.buf_size += pdev->params.rcv_buffer_offset;
        pkt->u1.rx.buf_size += CACHE_LINE_SIZE_MASK + 1;
        pkt->u1.rx.buf_size &= ~CACHE_LINE_SIZE_MASK;

        s_list_push_tail(&rxq->free_descq, &pkt->link);
    }

    DbgBreakIf(mem_size);
    DbgBreakIf(s_list_entry_cnt(&rxq->free_descq) != desc_cnt);
#endif
    return LM_STATUS_SUCCESS;
} /* alloc_l2rx_desc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_l2rx_resc(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    lm_rx_chain_t *rxq;
    u32_t idx;

#ifndef LM_NON_LEGACY_MODE_SUPPORT
    DbgBreakIf(pdev->rx_info.num_rxq > MAX_RX_CHAIN);

    for(idx = pdev->rx_info.num_rxq; idx < MAX_RX_CHAIN; idx++)
    {
        pdev->params.l2_rx_desc_cnt[idx] = 0;
        pdev->params.l2_rx_bd_page_cnt[idx] = 0;
    }
#endif
    for(idx = 0; idx < pdev->rx_info.num_rxq ; idx++)
    {
        rxq = &pdev->rx_info.chain[idx];
        rxq->idx = idx;
        rxq->cid_addr = GET_CID_ADDR(L2RX_CID_BASE + rxq->idx);

        s_list_init(&rxq->free_descq, NULL, NULL, 0);
        s_list_init(&rxq->active_descq, NULL, NULL, 0);

        lm_status = alloc_l2rx_desc(pdev, rxq);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        rxq->hw_con_idx_ptr = sblk_rx_con_idx_ptr(pdev, rxq);
    }

    return LM_STATUS_SUCCESS;
} /* init_l2rx_resc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_context_resc_5709(
    lm_device_t *pdev)
{
    phy_mem_block_t *ctx_mem;
    u32_t page_align_delta;
    lm_address_t mem_phy;
    u32_t ctx_in_mblk;
    u32_t mem_size;
    u8_t *mem_virt;
    u32_t ctx_cnt;

    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);
    DbgBreakIf(CTX_MBLK_SIZE & LM_PAGE_MASK);
    DbgBreakIf(MAX_CTX > 16 * 1024);
    DbgBreakIf(MAX_CTX * ONE_CTX_SIZE / CTX_MBLK_SIZE != NUM_CTX_MBLKS);
    DbgBreakIf((MAX_CTX * ONE_CTX_SIZE) % CTX_MBLK_SIZE);

    ctx_mem = &pdev->vars.ctx_mem[0];
    ctx_cnt = 0;

    while(ctx_cnt < MAX_CTX)
    {
        ctx_in_mblk = CTX_MBLK_SIZE / ONE_CTX_SIZE;
        if(ctx_cnt + ctx_in_mblk > MAX_CTX)
        {
            ctx_in_mblk = MAX_CTX - ctx_cnt;
        }

        mem_size = ctx_in_mblk * ONE_CTX_SIZE;

        mem_virt = (u8_t *) mm_alloc_phys_mem(
            pdev,
            mem_size + LM_PAGE_MASK,
            &mem_phy,
            PHYS_MEM_TYPE_NONCACHED,
            NULL);
        if(mem_virt == NULL)
        {
            return LM_STATUS_RESOURCE;
        }

        page_align_delta = mem_phy.as_u32.low & LM_PAGE_MASK;
        if(page_align_delta)
        {
            page_align_delta = LM_PAGE_SIZE - page_align_delta;
        }

        mem_virt += page_align_delta;
        LM_INC64(&mem_phy, page_align_delta);

        ctx_mem->start_phy = mem_phy;
        ctx_mem->start = mem_virt;
        ctx_mem->size = mem_size;
        ctx_mem++;

        ctx_cnt += mem_size / ONE_CTX_SIZE;
    }

    return LM_STATUS_SUCCESS;
} /* init_context_resc_5709 */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_init_resc(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    lm_address_t mem_phy;
    u8_t *mem_virt;
    u32_t mem_size;

    #ifndef EXCLUDE_KQE_SUPPORT
    lm_status = init_kwq_resc(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = init_kcq_resc(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    #endif

    #if INCLUDE_OFLD_SUPPORT
    lm_status = init_ofld_resc(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    #endif

    DbgBreakIf(sizeof(status_blk_combined_t) > STATUS_BLOCK_BUFFER_SIZE);
    DbgBreakIf(sizeof(statistics_block_t) > CHIP_STATS_BUFFER_SIZE);

    mem_size = STATUS_BLOCK_BUFFER_SIZE +
    #ifndef EXCLUDE_RSS_SUPPORT
        RSS_INDIRECTION_TABLE_SIZE +
        RSS_LOOKUP_TABLE_WA +
    #endif
        CHIP_STATS_BUFFER_SIZE;

    mem_virt = mm_alloc_phys_mem(
        pdev,
        mem_size,
        &mem_phy,
        PHYS_MEM_TYPE_NONCACHED,
        NULL);
    if(mem_virt == NULL)
    {
        return LM_STATUS_RESOURCE;
    }

    DbgBreakIf(mem_phy.as_u32.low & CACHE_LINE_SIZE_MASK);

    pdev->vars.status_virt = (status_blk_combined_t *) mem_virt;
    pdev->vars.status_phy = mem_phy;
    mem_virt += STATUS_BLOCK_BUFFER_SIZE;
    LM_INC64(&mem_phy, STATUS_BLOCK_BUFFER_SIZE);

    pdev->vars.stats_virt = (statistics_block_t *) mem_virt;
    pdev->vars.stats_phy = mem_phy;
    mem_virt += CHIP_STATS_BUFFER_SIZE;
    LM_INC64(&mem_phy, CHIP_STATS_BUFFER_SIZE);

    #ifndef EXCLUDE_RSS_SUPPORT
    pdev->rx_info.rss_ind_table_virt = mem_virt;
    pdev->rx_info.rss_ind_table_phy = mem_phy;
    #endif

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        lm_status = init_context_resc_5709(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    lm_status = init_l2tx_resc(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = init_l2rx_resc(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_clear_nwuf(pdev);

    return LM_STATUS_SUCCESS;
} /* lm_init_resc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
compute_crc32(
    u8_t *buf,
    u32_t buf_size)
{
    u32_t reg;
    u32_t tmp;
    u32_t j;
    u32_t k;

    reg = 0xffffffff;

    for(j = 0; j < buf_size; j++)
    {
        reg ^= buf[j];

        for(k = 0; k < 8; k++)
        {
            tmp = reg & 0x01;

            reg >>= 1;

            if(tmp)
            {
                reg ^= 0xedb88320;
            }
        }
    }

    return ~reg;
} /* compute_crc32 */



#define NUM_MC_HASH_REGISTERS                   8
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
set_mc_hash_reg(
    lm_device_t *pdev,
    lm_mc_table_t *mc_table)
{
    u32_t hash_reg[NUM_MC_HASH_REGISTERS];
    u32_t reg_idx;
    u32_t bit_pos;
    u32_t idx;
    u32_t crc32;

    /* Program the MC hash registers.
     *    The MAC hash registers are used to help discard unwanted
     *    multicast packets as they are received from the external
     *    media.  The destination address is fed into the normal CRC
     *    algorithm in order to generate a hash function.  The most
     *    significant bits of the CRC are then used without any inversion
     *    in reverse order to index into a hash table which is comprised
     *    of these MAC hash registers.  If the CRC is calculated by
     *    shifting right then the rightmost bits of the CRC can be
     *    directly used with no additional inversion or bit swapping
     *    required.  All four MAC hash registers are used such that
     *    register 1 bit-32 is the most significant hash table entry
     *    and register 8 bit-0 is the least significant hash table entry.
     *    This follows the normal big-endian ordering used throughout
     *    Teton.  Since there are 256 hash table entries, 8-bits are
     *    used from the CRC.  The hash registers are ignored if the
     *    receive MAC is in promiscuous mode. */
    for(idx = 0; idx < NUM_MC_HASH_REGISTERS; idx++)
    {
        hash_reg[idx] = 0;
    }

    for(idx = 0; idx < mc_table->entry_cnt; idx++)
    {
        crc32 = compute_crc32(
            mc_table->addr_arr[idx].mc_addr,
            ETHERNET_ADDRESS_SIZE);

        /* The most significant 7 bits of the CRC32 (no inversion),
         * are used to index into one of the possible 128 bit positions. */
        bit_pos = ~crc32 & 0xff;

        reg_idx = (bit_pos & 0xe0) >> 5;

        bit_pos &= 0x1f;

        hash_reg[reg_idx] |= (1 << bit_pos);
    }

    for(idx = 0; idx < NUM_MC_HASH_REGISTERS; idx++)
    {
        REG_WR(pdev, emac.emac_multicast_hash[idx], hash_reg[idx]);
    }
} /* set_mc_hash_reg */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_set_rx_mask(
    lm_device_t *pdev,
    u32_t user_idx,
    lm_rx_mask_t rx_mask)
{
    u32_t combined_rx_mask;
    u32_t invalid_rx_mask;
    u32_t sort_mode;
    u32_t rx_mode;
    u32_t val;
    u32_t idx;

    if(user_idx >= MAX_RX_FILTER_USER_CNT)
    {
        DbgBreakMsg("invalid user index.\n");

        return LM_STATUS_FAILURE;
    }

    combined_rx_mask = rx_mask;
    for(idx = 0; idx < MAX_RX_FILTER_USER_CNT; idx++)
    {
        if(idx != user_idx)
        {
            combined_rx_mask |= pdev->rx_info.mask[idx];
        }
    }

    /* Set up the rx_mode register. */
    invalid_rx_mask = combined_rx_mask;
    REG_RD(pdev, emac.emac_rx_mode, &rx_mode);

    if(invalid_rx_mask & LM_RX_MASK_ACCEPT_UNICAST)
    {
        invalid_rx_mask &= ~LM_RX_MASK_ACCEPT_UNICAST;
    }

    if(invalid_rx_mask & LM_RX_MASK_ACCEPT_MULTICAST)
    {
        invalid_rx_mask &= ~LM_RX_MASK_ACCEPT_MULTICAST;
    }

    if(invalid_rx_mask & LM_RX_MASK_ACCEPT_ALL_MULTICAST)
    {
        invalid_rx_mask &= ~LM_RX_MASK_ACCEPT_ALL_MULTICAST;
    }

    rx_mode &= ~EMAC_RX_MODE_FILT_BROADCAST;
    if(invalid_rx_mask & LM_RX_MASK_ACCEPT_BROADCAST)
    {
        invalid_rx_mask &= ~LM_RX_MASK_ACCEPT_BROADCAST;
    }
    else
    {
        rx_mode |= EMAC_RX_MODE_FILT_BROADCAST;
    }

    rx_mode &= ~(EMAC_RX_MODE_ACCEPT_RUNTS | EMAC_RX_MODE_ACCEPT_OVERSIZE);
    if(invalid_rx_mask & LM_RX_MASK_ACCEPT_ERROR_PACKET)
    {
        invalid_rx_mask &= ~LM_RX_MASK_ACCEPT_ERROR_PACKET;
        rx_mode |= EMAC_RX_MODE_ACCEPT_RUNTS |
            EMAC_RX_MODE_ACCEPT_OVERSIZE |
            EMAC_RX_MODE_NO_CRC_CHK;
    }

    rx_mode &= ~EMAC_RX_MODE_PROMISCUOUS;
    if(invalid_rx_mask & LM_RX_MASK_PROMISCUOUS_MODE)
    {
        invalid_rx_mask &= ~LM_RX_MASK_PROMISCUOUS_MODE;
        rx_mode |= EMAC_RX_MODE_PROMISCUOUS;
    }

    if(invalid_rx_mask)
    {
        DbgBreakMsg("Unknown rx_mask.\n");

        return LM_STATUS_FAILURE;
    }

    if(combined_rx_mask & LM_RX_MASK_ACCEPT_ALL_MULTICAST)
    {
        for(idx = 0; idx < NUM_MC_HASH_REGISTERS; idx++)
        {
            REG_WR(pdev, emac.emac_multicast_hash[idx], 0xffffffff);
        }
    }
    else if(combined_rx_mask & LM_RX_MASK_ACCEPT_MULTICAST)
    {
        set_mc_hash_reg(pdev, &pdev->mc_table);
    }
    else
    {
        for(idx = 0; idx < NUM_MC_HASH_REGISTERS; idx++)
        {
            REG_WR(pdev, emac.emac_multicast_hash[idx], 0);
        }
    }

    pdev->rx_info.mask[user_idx] = rx_mask;

    val = rx_mode | EMAC_RX_MODE_SORT_MODE;
    if(pdev->params.keep_vlan_tag)
    {
        val |= EMAC_RX_MODE_KEEP_VLAN_TAG;
    }
    REG_WR(pdev, emac.emac_rx_mode, val);

    /* Set up the sort_mode register. */
    sort_mode = 0;

    if(rx_mask & LM_RX_MASK_ACCEPT_UNICAST)
    {
        sort_mode |= 1 << user_idx;
    }

    if(rx_mask & LM_RX_MASK_ACCEPT_MULTICAST)
    {
        sort_mode |= RPM_SORT_USER0_MC_HSH_EN;
    }

    if(rx_mask & LM_RX_MASK_ACCEPT_ALL_MULTICAST)
    {
        sort_mode |= RPM_SORT_USER0_MC_EN;
    }

    if(rx_mask & LM_RX_MASK_ACCEPT_BROADCAST)
    {
        sort_mode |= RPM_SORT_USER0_BC_EN;
    }

    if(rx_mask & LM_RX_MASK_PROMISCUOUS_MODE)
    {
        sort_mode |= RPM_SORT_USER0_PROM_EN | RPM_SORT_USER0_PROM_VLAN;
    }

    switch(user_idx)
    {
        case RX_FILTER_USER_IDX0:
            REG_RD(pdev, rpm.rpm_sort_user0, &val);

            REG_WR(pdev, rpm.rpm_sort_user0, 0x00000000);
            REG_WR(pdev, rpm.rpm_sort_user0, sort_mode);

            val &= 0xffff;
            val &= ~(1 << user_idx);

            sort_mode |= val | RPM_SORT_USER0_ENA;
            REG_WR(pdev, rpm.rpm_sort_user0, sort_mode);
            break;

        case RX_FILTER_USER_IDX1:
            REG_RD(pdev, rpm.rpm_sort_user1, &val);

            REG_WR(pdev, rpm.rpm_sort_user1, 0x00000000);
            REG_WR(pdev, rpm.rpm_sort_user1, sort_mode);

            val &= 0xffff;
            val &= ~(1 << user_idx);

            sort_mode |= val | RPM_SORT_USER0_ENA;
            REG_WR(pdev, rpm.rpm_sort_user1, sort_mode);
            break;

        case RX_FILTER_USER_IDX2:
            REG_RD(pdev, rpm.rpm_sort_user2, &val);

            REG_WR(pdev, rpm.rpm_sort_user2, 0x00000000);
            REG_WR(pdev, rpm.rpm_sort_user2, sort_mode);

            val &= 0xffff;
            val &= ~(1 << user_idx);

            sort_mode |= val | RPM_SORT_USER0_ENA;
            REG_WR(pdev, rpm.rpm_sort_user2, sort_mode);
            break;

        case RX_FILTER_USER_IDX3:
            REG_RD(pdev, rpm.rpm_sort_user3, &val);

            REG_WR(pdev, rpm.rpm_sort_user3, 0x00000000);
            REG_WR(pdev, rpm.rpm_sort_user3, sort_mode);

            val &= 0xffff;
            val &= ~(1 << user_idx);

            sort_mode |= val | RPM_SORT_USER0_ENA;
            REG_WR(pdev, rpm.rpm_sort_user3, sort_mode);
            break;

        default:
            DbgBreakMsg("invalid user idx.\n");

            break;
    }

    /* Set rx_flood for L2. */
    REG_RD_IND(pdev, 0xe0024, &val);
    val &= ~(1 << user_idx);

    if(rx_mask & (LM_RX_MASK_ACCEPT_MULTICAST |
                  LM_RX_MASK_ACCEPT_ALL_MULTICAST |
                  LM_RX_MASK_ACCEPT_BROADCAST |
                  LM_RX_MASK_PROMISCUOUS_MODE))
    {
        val |= (1 << user_idx);
    }

    REG_WR_IND(pdev, 0xe0024, val);

    return LM_STATUS_SUCCESS;
} /* lm_set_rx_mask */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_add_mc(
    lm_device_t *pdev,
    u8_t *mc_addr)
{
    lm_mc_entry_t *mc_entry;
    u32_t cnt;

    DbgMessage(pdev, VERBOSE, "### lm_add_mc\n");

    for(cnt = 0; cnt < pdev->mc_table.entry_cnt; cnt++)
    {
        mc_entry = &pdev->mc_table.addr_arr[cnt];

        if(IS_ETH_ADDRESS_EQUAL(mc_entry->mc_addr, mc_addr))
        {
            mc_entry->ref_cnt++;

            return LM_STATUS_SUCCESS;
        }
    }

    if(pdev->mc_table.entry_cnt >= LM_MAX_MC_TABLE_SIZE)
    {
        DbgBreakMsg("No entry in MC table\n");

        return LM_STATUS_FAILURE;
    }

    mc_entry = &pdev->mc_table.addr_arr[pdev->mc_table.entry_cnt];
    pdev->mc_table.entry_cnt++;

    mc_entry->ref_cnt = 1;

    COPY_ETH_ADDRESS(mc_addr, mc_entry->mc_addr);

    (void) lm_set_rx_mask(
        pdev,
        RX_FILTER_USER_IDX0,
        pdev->rx_info.mask[RX_FILTER_USER_IDX0] | LM_RX_MASK_ACCEPT_MULTICAST);

    return LM_STATUS_SUCCESS;
} /* lm_add_mc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_del_mc(
    lm_device_t *pdev,
    u8_t *mc_addr)
{
    lm_mc_entry_t *mc_entry;
    u32_t cnt;

    for(cnt = 0; cnt < pdev->mc_table.entry_cnt; cnt++)
    {
        mc_entry = &pdev->mc_table.addr_arr[cnt];

        if(IS_ETH_ADDRESS_EQUAL(mc_entry->mc_addr, mc_addr))
        {
            mc_entry->ref_cnt--;

            /* No more instance left, remove the address from the table.
             * Move the last entry in the table to the deleted slot. */
            if(mc_entry->ref_cnt == 0)
            {
                if(pdev->mc_table.entry_cnt > 1)
                {
                    *mc_entry = pdev->mc_table.addr_arr[pdev->mc_table.entry_cnt-1];
                }

                pdev->mc_table.entry_cnt--;

                /* Update the receive mask if the table is empty. */
                if(pdev->mc_table.entry_cnt == 0)
                {
                    pdev->rx_info.mask[RX_FILTER_USER_IDX0] &=
                            ~LM_RX_MASK_ACCEPT_MULTICAST;
                }

                (void) lm_set_rx_mask(
                        pdev,
                        RX_FILTER_USER_IDX0,
                        pdev->rx_info.mask[RX_FILTER_USER_IDX0]);
            }

            return LM_STATUS_SUCCESS;
        }
    }

    DbgBreakMsg("Mc address not in the table\n");

    return LM_STATUS_FAILURE;
} /* lm_del_mc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_clear_mc(lm_device_t *pdev)
{
    DbgMessage(pdev, VERBOSE, "### lm_clear_mc\n");

    pdev->mc_table.entry_cnt = 0;

    (void) lm_set_rx_mask(
        pdev,
        RX_FILTER_USER_IDX0,
        pdev->rx_info.mask[RX_FILTER_USER_IDX0] & ~LM_RX_MASK_ACCEPT_MULTICAST);
} /* lm_clear_mc */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_get_stats(
    lm_device_t *pdev,
    lm_stats_t stats_type,
    u64_t *stats_cnt)
{
    volatile statistics_block_t *sb;
    lm_status_t lm_status;
    lm_u64_t *stats;
    u32_t reg_val;
    u32_t val;

    //
    // The fix of CQ#29454 caused CQ#30307 -
    // Bacs: Bogus counters on 5708 under statistics tab
    // So far, Windows never see CQ#29454 problem.
    // Remove the fix right now
    //

    /* CQ#29454 - statistics corruption. */
    //REG_RD(pdev, hc.hc_stats_ticks, &val);
    //REG_WR(pdev, hc.hc_stats_ticks, 0);

    REG_WR(pdev, hc.hc_command, HC_COMMAND_STATS_NOW);
    REG_RD(pdev, hc.hc_command, &reg_val);
    mm_wait(pdev, 5);

    lm_status = LM_STATUS_SUCCESS;
    sb = pdev->vars.stats_virt;
    stats = (lm_u64_t *) stats_cnt;

    switch(stats_type)
    {
        case LM_STATS_FRAMES_XMITTED_OK:
            stats->as_u32.low = sb->stat_IfHCOutUcastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCOutUcastPkts_hi;

            LM_INC64(stats, sb->stat_IfHCOutMulticastPkts_lo);
            stats->as_u32.high += sb->stat_IfHCOutMulticastPkts_hi;

            LM_INC64(stats, sb->stat_IfHCOutBroadcastPkts_lo);
            stats->as_u32.high += sb->stat_IfHCOutBroadcastPkts_hi;
            break;

        case LM_STATS_FRAMES_RECEIVED_OK:
            stats->as_u32.low = sb->stat_IfHCInUcastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCInUcastPkts_hi;

            LM_INC64(stats, sb->stat_IfHCInMulticastPkts_lo);
            stats->as_u32.high += sb->stat_IfHCInMulticastPkts_hi;

            LM_INC64(stats, sb->stat_IfHCInBroadcastPkts_lo);
            stats->as_u32.high += sb->stat_IfHCInBroadcastPkts_hi;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t,
                         com.com_scratch[0])+
                         COM_HSI_OFFSETOFF(com_l2_iscsi_no_buffer),
                         &val);
            if((stats->as_u32.high == 0 && stats->as_u32.low) &&
               (stats->as_u32.low < val))
            {
                /* due to asynchrous nature of reading the counters
                 * from status block and reading the counters from
                 * chip scratchpad mem, it is possible that the values
                 * are out of syn */
                stats->as_u32.low = 0;
            }
            else
            {
                LM_DEC64(stats, val);
            }

            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t,
                         com.com_scratch[0])+
                         COM_HSI_OFFSETOFF(com_l2_no_buffer),
                         &val);
            if((stats->as_u32.high == 0 && stats->as_u32.low) &&
               (stats->as_u32.low < val))
            {
                /* due to asynchrous nature of reading the counters
                 * from status block and reading the counters from
                 * chip scratchpad mem, it is possible that the values
                 * are out of syn */
                stats->as_u32.low = 0;
            }
            else
            {
                LM_DEC64(stats, val);
            }
            break;

        case LM_STATS_ERRORED_RECEIVE_CNT:
            stats->as_u32.low = pdev->rx_info.stats.err;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_RCV_CRC_ERROR:
            stats->as_u32.low = sb->stat_Dot3StatsFCSErrors;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_ALIGNMENT_ERROR:
            stats->as_u32.low = sb->stat_Dot3StatsAlignmentErrors;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_SINGLE_COLLISION_FRAMES:
            stats->as_u32.low = sb->stat_Dot3StatsSingleCollisionFrames;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_MULTIPLE_COLLISION_FRAMES:
            stats->as_u32.low = sb->stat_Dot3StatsMultipleCollisionFrames;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_FRAMES_DEFERRED:
            stats->as_u32.low = sb->stat_Dot3StatsDeferredTransmissions;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_MAX_COLLISIONS:
            stats->as_u32.low = sb->stat_Dot3StatsExcessiveCollisions;
            break;

        case LM_STATS_UNICAST_FRAMES_XMIT:
            stats->as_u32.low = sb->stat_IfHCOutUcastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCOutUcastPkts_hi;
            break;

        case LM_STATS_MULTICAST_FRAMES_XMIT:
            stats->as_u32.low = sb->stat_IfHCOutMulticastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCOutMulticastPkts_hi;
            break;

        case LM_STATS_BROADCAST_FRAMES_XMIT:
            stats->as_u32.low = sb->stat_IfHCOutBroadcastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCOutBroadcastPkts_hi;
            break;

        case LM_STATS_UNICAST_FRAMES_RCV:
            stats->as_u32.low = sb->stat_IfHCInUcastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCInUcastPkts_hi;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t,
                         com.com_scratch[0])+
                         COM_HSI_OFFSETOFF(com_unicast_no_buffer),
                         &val);
            if((stats->as_u32.high == 0 && stats->as_u32.low) &&
               (stats->as_u32.low < val))
            {
                /* due to asynchrous nature of reading the counters
                 * from status block and reading the counters from
                 * chip scratchpad mem, it is possible that the values
                 * are out of syn */
                stats->as_u32.low = 0;
            }
            else
            {
                LM_DEC64(stats, val);
            }
            break;

        case LM_STATS_MULTICAST_FRAMES_RCV:
            stats->as_u32.low = sb->stat_IfHCInMulticastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCInMulticastPkts_hi;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t,
                         com.com_scratch[0])+
                         COM_HSI_OFFSETOFF(com_mcast_no_buffer),
                         &val);

            if((stats->as_u32.high == 0 && stats->as_u32.low) &&
               (stats->as_u32.low < val))
            {
                /* due to asynchrous nature of reading the counters
                 * from status block and reading the counters from
                 * chip scratchpad mem, it is possible that the values
                 * are out of syn */
                stats->as_u32.low = 0;
            }
            else
            {
                LM_DEC64(stats, val);
            }
            break;

        case LM_STATS_BROADCAST_FRAMES_RCV:
            stats->as_u32.low = sb->stat_IfHCInBroadcastPkts_lo;
            stats->as_u32.high = sb->stat_IfHCInBroadcastPkts_hi;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t,
                         com.com_scratch[0])+
                         COM_HSI_OFFSETOFF(com_bcast_no_buffer),
                         &val);
            if((stats->as_u32.high == 0 && stats->as_u32.low) &&
               (stats->as_u32.low < val))
            {
                /* due to asynchrous nature of reading the counters
                 * from status block and reading the counters from
                 * chip scratchpad mem, it is possible that the values
                 * are out of syn */
                stats->as_u32.low = 0;
            }
            else
            {
                LM_DEC64(stats, val);
            }
            break;

        case LM_STATS_ERRORED_TRANSMIT_CNT:
        case LM_STATS_RCV_OVERRUN:
        case LM_STATS_XMIT_UNDERRUN:
            /* These counters are always zero. */
            stats->as_u32.low = 0;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_RCV_NO_BUFFER_DROP:
            /* com_no_buffer */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_unicast_no_buffer),
                &val);
            stats->as_u32.low = val;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_mcast_no_buffer),
                &val);
            stats->as_u32.low += val;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_bcast_no_buffer),
                &val);
            stats->as_u32.low += val;

            stats->as_u32.high = 0;
            break;

        case LM_STATS_BYTES_RCV:
            stats->as_u32.low = sb->stat_IfHCInOctets_lo;
            stats->as_u32.high = sb->stat_IfHCInOctets_hi;
            break;

        case LM_STATS_BYTES_XMIT:
            stats->as_u32.low = sb->stat_IfHCOutOctets_lo;
            stats->as_u32.high = sb->stat_IfHCOutOctets_hi;
            break;

        case LM_STATS_IF_IN_DISCARDS:
            /* com_no_buffer */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_unicast_no_buffer),
                &val);
            stats->as_u32.low = val;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_mcast_no_buffer),
                &val);
            stats->as_u32.low += val;
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_bcast_no_buffer),
                &val);
            stats->as_u32.low += val;
            stats->as_u32.low += sb->stat_Dot3StatsFCSErrors;

            stats->as_u32.high = 0;
            break;

        case LM_STATS_XMIT_DISCARDS:
        case LM_STATS_IF_IN_ERRORS:
        case LM_STATS_IF_OUT_ERRORS:
            stats->as_u32.low = 0;
            stats->as_u32.high = 0;
            break;

        case LM_STATS_DIRECTED_BYTES_RCV:
            /* rxp_unicast_bytes_rcvd */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(rxp_unicast_bytes_rcvd)+4,
                &stats->as_u32.low);
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(rxp_unicast_bytes_rcvd),
                &stats->as_u32.high);
            break;

        case LM_STATS_MULTICAST_BYTES_RCV:
            /* rxp_multicast_bytes_rcvd */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(rxp_multicast_bytes_rcvd)+4,
                &stats->as_u32.low);
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(rxp_multicast_bytes_rcvd),
                &stats->as_u32.high);
            break;

        case LM_STATS_BROADCAST_BYTES_RCV:
            /* rxp_broadcast_bytes_rcvd */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(rxp_broadcast_bytes_rcvd)+4,
                &stats->as_u32.low);
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+RXP_HSI_OFFSETOFF(rxp_broadcast_bytes_rcvd),
                &stats->as_u32.high);
            break;

        case LM_STATS_DIRECTED_BYTES_XMIT:
            /* unicast_bytes_xmit_lo */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(unicast_bytes_xmit)+4,
                &stats->as_u32.low);
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(unicast_bytes_xmit),
                &stats->as_u32.high);
            break;

        case LM_STATS_MULTICAST_BYTES_XMIT:
            /* multicast_bytes_xmit */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(multicast_bytes_xmit)+4,
                &stats->as_u32.low);
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(multicast_bytes_xmit),
                &stats->as_u32.high);
            break;

        case LM_STATS_BROADCAST_BYTES_XMIT:
            /* broadcast_bytes_xmit */
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(broadcast_bytes_xmit)+4,
                &stats->as_u32.low);
            REG_RD_IND(
                pdev,
                OFFSETOF(reg_space_t, tpat.tpat_scratch[0])+TPAT_HSI_OFFSETOFF(broadcast_bytes_xmit),
                &stats->as_u32.high);
            break;

        default:
            stats->as_u32.low = 0;
            stats->as_u32.high = 0;

            lm_status = LM_STATUS_INVALID_PARAMETER;
            break;
    }

    //REG_WR(pdev, hc.hc_stats_ticks, val);

    return lm_status;
} /* lm_get_stats */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_nwuf_t *
find_nwuf(
    lm_nwuf_list_t *nwuf_list,
    u32_t mask_size,
    u8_t *byte_mask,
    u8_t *pattern,
    u32_t max_nwuf_cnt)
{
    lm_nwuf_t *nwuf;
    u8_t found;
    u32_t idx;
    u32_t j;
    u32_t k;

    for(idx = 0; idx < max_nwuf_cnt; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];

        if((nwuf->size&0xffff) != mask_size)
        {
            continue;
        }

        found = TRUE;
        for(j = 0; j < mask_size && found == TRUE; j++)
        {
            if(nwuf->mask[j] != byte_mask[j])
            {
                found = FALSE;
                break;
            }

            for(k = 0; k < 8; k++)
            {
                if((byte_mask[j] & (1 << k)) &&
                    (nwuf->pattern[j*8 + k] != pattern[j*8 + k]))
                {
                    found = FALSE;
                    break;
                }
            }
        }

        if(found)
        {
            return nwuf;
        }
    }

    return NULL;
} /* find_nwuf */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_add_nwuf(
    lm_device_t *pdev,
    u32_t pattern_size,
    u32_t mask_size,
    u8_t *byte_mask,
    u8_t *pattern)
{
    lm_nwuf_t *nwuf;
    u32_t idx;
/*
    u32_t i;
*/
    u32_t j;
    u32_t k;
    u32_t l;
    u32_t combind_size;
    u32_t max_nwuf_cnt;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        max_nwuf_cnt = LM_MAX_NWUF_CNT_5709;
    }
    else
    {
        max_nwuf_cnt = LM_MAX_NWUF_CNT;
    }

    combind_size = (pattern_size<<16) & 0xffff0000;
    combind_size |= mask_size;
    pattern_size &= 0xffff;
    mask_size &= 0xffff;


        //DbgBreakIf(mask_size == 0xc &&pattern_size == 0x4a);


    if(mask_size == 0 || mask_size > LM_NWUF_PATTERN_MASK_SIZE)
    {
        DbgBreakMsg("Invalid byte mask size\n");

        return LM_STATUS_FAILURE;
    }

    /* If this is a duplicate entry, we are done. */
    nwuf = find_nwuf(
            &pdev->nwuf_list,
            mask_size,
            byte_mask, pattern,
            max_nwuf_cnt);

    if(nwuf)
    {
        DbgMessage(pdev, INFORM, "Duplicated nwuf entry.\n");

        return LM_STATUS_EXISTING_OBJECT;
    }

    /* Find an empty slot. */
    nwuf = NULL;
    for(idx = 0; idx < max_nwuf_cnt; idx++)
    {
        if(pdev->nwuf_list.nwuf_arr[idx].size == 0)
        {
            nwuf = &pdev->nwuf_list.nwuf_arr[idx];
            break;
        }
    }

    /*
     * LHDBG_PRINT(("%p Adding NWUF[%d], mask size: %d, pattern size: %d\n",
                pdev,idx,mask_size,pattern_size));
    LHDBG_PRINT(("mask array:\n"));

    for (i=0;i<mask_size;i++)
    {
        if (0 == i%16) LH_PRINTK(("\n"));
        LH_PRINTK(("%02x ", byte_mask[i]));
    }
    LH_PRINTK(("\npattern:\n"));

    for (i=0;i<mask_size;i++)
    {
        for (j=0;j<8;j++)
        {
            if (0 == (i*8+j)%16)
            {
                LH_PRINTK(("\n"));
            }
            if (byte_mask[i] & 1<<j)
            {
                LH_PRINTK(("[%02x] ",pattern[i*8+j]));
            }
            else
            {
                if (pattern_size && i*8+j>=pattern_size)
                {
                    LH_PRINTK(("-%02x- ",pattern[i*8+j]));
                }
                else
                {
                    LH_PRINTK((" %02x  ",pattern[i*8+j]));
                }

            }
        }
    }
    LH_PRINTK(("\n"));
*/

    if(nwuf == NULL)
    {
        DbgMessage(pdev, WARN, "Cannot add Nwuf, exceeded maximum.\n");

        return LM_STATUS_RESOURCE;
    }

    pdev->nwuf_list.cnt++;

    /* Save nwuf data. */
    nwuf->size = mask_size;

    if (pattern_size)
    {
        nwuf->size = combind_size;
        goto _handle_win7_pattern;
    }

    for(j = 0; j < mask_size; j++)
    {
        nwuf->mask[j] = byte_mask[j];

        for(k = 0; k < 8; k++)
        {
            if(byte_mask[j] & (1 << k))
            {
                nwuf->pattern[j*8 + k] = pattern[j*8 + k];
            }
            else
            {
                nwuf->pattern[j*8 + k] = 0;
            }
        }
    }

    /* The byte patterns immediately following the byte that is enabled
     * for comparision need to be set to 0xff.  This will help facilitate
     * the programming of pattern onto the chip.  The end of the pattern is
     * indicated by the first 0xff byte that is not enabled for comparision. */
    if(byte_mask[mask_size-1])
    {
        k = 8;
        while(k)
        {
            k--;
            if(byte_mask[mask_size-1] & (1 << k))
            {
                break;
            }

            nwuf->pattern[(mask_size-1)*8 + k] = 0xff;
        }
    }

    /* Set the rest of the pattern to 0xff. */
    for(j = mask_size; j < LM_NWUF_PATTERN_MASK_SIZE; j++)
    {
        nwuf->mask[j] = 0;

        for(k = 0; k < 8; k++)
        {
            nwuf->pattern[j*8 + k] = 0xff;
        }
    }
/*
    LHDBG_PRINT(("Dumping pattern before return\n"));
    for (i=0;i<128;i++)
    {
        if (i!=0 && i%16==0)
        {
            LH_PRINTK(("\n"));
        }

        LH_PRINTK(("%02x ",nwuf->pattern[i]));

    }
    LH_PRINTK(("\nEnd of add_nwuf\n"));
*/
    return LM_STATUS_SUCCESS;
_handle_win7_pattern:
    /*
     * this is new for win7
     */
    l=0;

    /*for lxdiag build*/
#ifdef LINUX
	{
		u8_t idx;
		for (idx=0; idx< LM_NWUF_PATTERN_MASK_SIZE; idx++)
					nwuf->mask[idx] = 0;
	}
#else
    memset(nwuf->mask,0,LM_NWUF_PATTERN_MASK_SIZE);
#endif

    for(j = 0; j < mask_size ; j++)
    {
        nwuf->mask[j] = byte_mask[j];

        for(k = 0; k < 8 ; k++)
        {
            if ( l<pattern_size )
            {
                if(byte_mask[j] & (1 << k))
                {
                    nwuf->pattern[j*8 + k] = pattern[j*8 + k];
                }
                else
                {
                    nwuf->pattern[j*8 + k] = 0;
                }
            }
            else
            {
                nwuf->pattern[j*8 + k] = 0xff;
            }
            l++;
        }
    }
/*
    LHDBG_PRINT(("Dumping pattern before return\n"));
    for (i=0;i<128;i++)
    {
        if (i!=0 && i%16==0)
        {
            LH_PRINTK(("\n"));
        }

        LH_PRINTK(("%02x ",nwuf->pattern[i]));

    }
    LH_PRINTK(("\nEnd of add_nwuf\n"));
*/
    return LM_STATUS_SUCCESS;
} /* lm_add_nwuf */


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_del_nwuf(
    lm_device_t *pdev,
    u32_t mask_size,
    u8_t *byte_mask,
    u8_t *pattern)
{
    lm_nwuf_t *nwuf;
    u32_t k;
    u32_t max_nwuf_cnt;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        max_nwuf_cnt = LM_MAX_NWUF_CNT_5709;
    }
    else
    {
        max_nwuf_cnt = LM_MAX_NWUF_CNT;
    }

    mask_size &= 0xffff;
    if(mask_size == 0 || mask_size > LM_NWUF_PATTERN_MASK_SIZE)
    {
        DbgBreakMsg("Invalid byte mask size\n");

        return LM_STATUS_FAILURE;
    }

    /* Look for a matching pattern. */
    nwuf = find_nwuf(
            &pdev->nwuf_list,
            mask_size,
            byte_mask,
            pattern,
            max_nwuf_cnt);

    if(nwuf == NULL)
    {
        return LM_STATUS_OBJECT_NOT_FOUND;
    }

    nwuf->size = 0;

    for(k = 0; k < LM_NWUF_PATTERN_MASK_SIZE; k++)
    {
        nwuf->mask[k] = 0;
    }

    for(k = 0; k < LM_NWUF_PATTERN_SIZE; k++)
    {
        nwuf->pattern[k] = 0xff;
    }

    pdev->nwuf_list.cnt--;

    return LM_STATUS_SUCCESS;
} /* lm_del_nwuf */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_clear_nwuf(
    lm_device_t *pdev)
{
    u32_t j;
    u32_t k;
    u32_t max_nwuf_cnt;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        max_nwuf_cnt = LM_MAX_NWUF_CNT_5709;
    }
    else
    {
        max_nwuf_cnt = LM_MAX_NWUF_CNT;
    }

    for(j = 0; j < max_nwuf_cnt; j++)
    {
        pdev->nwuf_list.nwuf_arr[j].size = 0;

        for(k = 0; k < LM_NWUF_PATTERN_MASK_SIZE; k++)
        {
            pdev->nwuf_list.nwuf_arr[j].mask[k] = 0;
        }

        for(k = 0; k < LM_NWUF_PATTERN_SIZE; k++)
        {
            pdev->nwuf_list.nwuf_arr[j].pattern[k] = 0xff;
        }
    }

    pdev->nwuf_list.cnt = 0;
} /* lm_clear_nwuf */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
init_nwuf_5709(
    lm_device_t *pdev,
    lm_nwuf_list_t *nwuf_list)
{
    lm_nwuf_t *nwuf;
    u16_t prev_val;
    u32_t nwuf_len;
    u32_t nwuf_cnt;
    u32_t offset;
    u8_t mask;
    u32_t val;
    u32_t idx;
    u8_t bit;
    u16_t pattern_size;
    u32_t nwuf_size[LM_MAX_NWUF_CNT_5709];

    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5709);
    DbgBreakIf(LM_NWUF_PATTERN_SIZE > 128);
    DbgBreakIf(LM_MAX_NWUF_CNT_5709 > 8);

    REG_WR(pdev, rpm.rpm_acpi_byte_enable_ctrl, RPM_ACPI_BYTE_ENABLE_CTRL_INIT);

    for(idx = 0; idx < LM_MAX_NWUF_CNT_5709; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        nwuf_size[idx] = nwuf->size;
    }
    for(idx = 0; idx < 1000; idx++)
    {
        mm_wait(pdev, 5);

        REG_RD(pdev, rpm.rpm_acpi_byte_enable_ctrl, &val);
        if((val & RPM_ACPI_BYTE_ENABLE_CTRL_INIT) == 0)
        {
            break;
        }
    }
    DbgBreakIf(val & RPM_ACPI_BYTE_ENABLE_CTRL_INIT);

    val = 0;
    for(idx = 0; idx < 4; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        pattern_size = nwuf->size >>16;
        nwuf->size &= 0xffff;

        DbgBreakIf(nwuf->size > LM_NWUF_PATTERN_MASK_SIZE);

        if(nwuf->size == 0)
        {
            continue;
        }
        if (pattern_size)
        {
            val |= (pattern_size) << ((3 - idx) * 8);
        }
        else
        {
            val |= (nwuf->size * 8) << ((3 - idx) * 8);
        }
    }
    REG_WR(pdev, rpm.rpm_acpi_pattern_len0, val);

    val = 0;
    for(idx = 4; idx < LM_MAX_NWUF_CNT_5709; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        pattern_size = nwuf->size >>16;
        nwuf->size &= 0xffff;

        DbgBreakIf(nwuf->size > LM_NWUF_PATTERN_MASK_SIZE);

        if(nwuf->size == 0)
        {
            continue;
        }

        if (pattern_size)
        {
            val |= (pattern_size) << ((7 - idx) * 8);
        }
        else
        {
            val |= (nwuf->size * 8) << ((7 - idx) * 8);
        }

        // old code val |= (nwuf->size * 8) << ((7 - idx) * 8);
    }
    REG_WR(pdev, rpm.rpm_acpi_pattern_len1, val);

    for(offset = 0; offset < LM_NWUF_PATTERN_SIZE; offset++)
    {
        val = 0;

        for(idx = 0; idx < LM_MAX_NWUF_CNT_5709; idx++)
        {
            nwuf = &nwuf_list->nwuf_arr[idx];
            pattern_size = nwuf_size[idx]>>16;

            if(nwuf->size == 0 || offset > nwuf->size * 8)
            {
                continue;
            }

            mask = nwuf->mask[offset/8];
            bit = offset % 8;

            if(mask & (1 << bit))
            {
                val |= 1 << idx;
            }
        }

        REG_WR(pdev, rpm.rpm_acpi_data, val);

        /* Perform the Write to the byte enable memory, The actual pattern
         * byte enables start from byte address 2. the first two bytes of
         * a packet are always 0 and inserted by EMAC to align the IP header
         * to 4-byte boudary. */
        REG_WR(
            pdev,
            rpm.rpm_acpi_byte_enable_ctrl,
            RPM_ACPI_BYTE_ENABLE_CTRL_WR | offset);
        REG_RD(pdev, rpm.rpm_acpi_byte_enable_ctrl, &val);
        DbgBreakIf(val & RPM_ACPI_BYTE_ENABLE_CTRL_WR);
    }

    nwuf_cnt = 0;

    for(idx = 0; idx < LM_MAX_NWUF_CNT_5709; idx++)
    {
        REG_WR(
            pdev,
            rpm.rpm_acpi_pattern_ctrl,
            RPM_ACPI_PATTERN_CTRL_CRC_SM_CLR|idx);
        REG_RD(pdev, rpm.rpm_acpi_pattern_ctrl, &val);
        DbgBreakIf(val & RPM_ACPI_PATTERN_CTRL_CRC_SM_CLR);

        nwuf = &nwuf_list->nwuf_arr[idx];
        if(nwuf->size == 0)
        {
            continue;
        }
        pattern_size = nwuf_size[idx]>>16;

        /* The CRC calculation is done on 64-bit data. So the length of the
         * pattern over which CRC needs to be calculated needs to be padded
         * by 0 to 7 bytes to make it 8 byte aligned. */

        if (pattern_size)
        {
            nwuf_len = pattern_size;
        }
        else
        {
            nwuf_len = (nwuf->size * 8);
        }
        nwuf_len += 2;  /* 2-byte padding. */
        nwuf_len = (nwuf_len + 3) & ~3;

        prev_val = 0;

        for(offset = 0; offset < nwuf_len; offset += 4)
        {
            val = 0;

            for(bit = 0; bit < 4; bit++)
            {
                if (pattern_size)
                {
                    if(offset < pattern_size)
                    {
                        mask = nwuf->mask[offset/8];
                    }
                    else
                    {
                        mask = 0;
                    }
                }
                else
                {
                    if(offset < nwuf->size * 8)
                    {
                        mask = nwuf->mask[offset/8];
                    }
                    else
                    {
                        mask = 0;
                    }
                }
                if(mask & (1 << (bit + (offset % 8))))
                {
                    val |= nwuf->pattern[offset+bit] << ((3 - bit) * 8);
                }
            }

            REG_WR(pdev, rpm.rpm_acpi_data, (prev_val << 16) | (val >> 16));
            prev_val = (u16_t) val;

            REG_WR(
                pdev,
                rpm.rpm_acpi_pattern_ctrl,
                RPM_ACPI_PATTERN_CTRL_WR | idx);
            REG_RD(pdev, rpm.rpm_acpi_pattern_ctrl, &val);
            DbgBreakIf(val & RPM_ACPI_PATTERN_CTRL_WR);
        }

        nwuf_cnt++;
    }
    for(idx = 0; idx < LM_MAX_NWUF_CNT_5709; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        nwuf->size = nwuf_size[idx];
    }

    return nwuf_cnt;
} /* init_nwuf_5709 */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
init_nwuf_5706(
    lm_device_t *pdev,
    lm_nwuf_list_t *nwuf_list)
{
    typedef union _acpi_wol_pat_t
    {
        #if defined(LITTLE_ENDIAN)
        struct _acpi_wol_pat_as_u8_t
        {
            u8_t pat[7];
            u8_t ena;
        } as_u8;

        struct _acpi_wol_pat_as_u32_t
        {
            u32_t low;
            u32_t high;
        } as_u32;
        #elif defined(BIG_ENDIAN)
        struct _acpi_wol_pat_as_u8_t
        {
            u8_t ena;
            u8_t pat[7];
        } as_u8;

        struct _acpi_wol_pat_as_u32_t
        {
            u32_t high;
            u32_t low;
        } as_u32;
        #endif
    } acpi_wol_pat_t;

    u32_t filler_pattern_idx;
    acpi_wol_pat_t wol_pat;
    u32_t pattern_cnt;
    u8_t val;
    u32_t j;
    u32_t k;
    u8_t idx;
    u32_t nwuf_size[LM_MAX_NWUF_CNT];
    lm_nwuf_t *nwuf;

    /*
     * 06/08 doesn't seem to have pattern size like those of 09
     */
    for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        nwuf_size[idx] = nwuf->size;
        nwuf->size &= 0xffff;
    }

    DbgBreakIf(LM_NWUF_PATTERN_SIZE > 128);
    DbgBreakIf(LM_MAX_NWUF_CNT > 7);
    DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5706 &&
               CHIP_NUM(pdev) != CHIP_NUM_5708);

    /* If a pattern is not present, we will fill the pattern buffer
     * with the pattern with this index.  The pattern buffer cannot
     * have an empty pattern otherwise we will get a false detection. */
    filler_pattern_idx = 0;

    /* Find out the number of patterns. */
    pattern_cnt = 0;
    for(k = 0; k < LM_MAX_NWUF_CNT; k++)
    {
        if(nwuf_list->nwuf_arr[k].size)
        {
            pattern_cnt++;
            filler_pattern_idx = k;
        }
    }

    /* Program the pattern. */
    for(j = 0; j < LM_NWUF_PATTERN_SIZE; j++)
    {
        wol_pat.as_u32.low = 0x0;
        wol_pat.as_u32.high = 0x0;

        /* Build the enable bits. */
        wol_pat.as_u8.ena = 0;
        for(k = 0; k < LM_MAX_NWUF_CNT; k++)
        {
            if(nwuf_list->nwuf_arr[k].size == 0)
            {
                val = nwuf_list->nwuf_arr[filler_pattern_idx].mask[j/8];
            }
            else if((j/8) >= nwuf_list->nwuf_arr[k].size)
            {
                val = 0;
            }
            else
            {
                val = nwuf_list->nwuf_arr[k].mask[j/8];
            }

            /* Determine if a byte is enabled for comparision. */
            if(val & (1 << (j % 8)))
            {
                wol_pat.as_u8.ena |= 1 << k;
            }
        }

        DbgMessage1(pdev, VERBOSE, "%02x: ", j);

        /* Enter the byte of each pattern that will be used for comparison. */
        for(k = 0; k < LM_MAX_NWUF_CNT; k++)
        {
            /* Check to see if we are at the end of the pattern.  0xff
             * will terminate the pattern.  If there is no pattern present
             * we cannot terminate with 0xff. */
            if(nwuf_list->nwuf_arr[k].size == 0)
            {
                val = nwuf_list->nwuf_arr[filler_pattern_idx].pattern[j];
                DbgMessage(pdev, VERBOSE, "xx ");
            }
            else if((j/8) >= nwuf_list->nwuf_arr[k].size)
            {
                val = 0xff;
                DbgMessage(pdev, VERBOSE, "ff ");
            }
            else
            {
                val = nwuf_list->nwuf_arr[k].pattern[j];
                DbgMessage1(pdev, VERBOSE, "%02x ", val);
            }

            /* Format of the ACPI_WOL pattern from low address to high on a
             * little endian system:
             *    pat0_6 pat0_5 pat0_4 pat0_3 pat0_2 pat0_1 pat0_0 ena0
             *
             * on a big endian system:
             *    ena0 pat0_0 pat0_1 pat0_2 pat0_3 pat0_4 pat0_5 pat0_6 */
            #if defined(LITTLE_ENDIAN)
            wol_pat.as_u8.pat[6-k] = val;
            #elif defined(BIG_ENDIAN)
            wol_pat.as_u8.pat[k] = val;
            #endif
        }

        DbgMessage2(pdev, VERBOSE, "   %08x %08x\n",
            wol_pat.as_u32.high, wol_pat.as_u32.low);

        /* Swap the even 64-bit word with the odd 64-bit word.  This is
         * they way it works.  Don't ask why.  So the values written
         * to the header buffer looks as follows:
         *    0x0000:  ena1   pat1_0 pat1_1 pat1_2
         *    0x0004:  pat1_3 pat1_4 pat1_5 pat1_6
         *    0x0008:  ena0   pat0_0 pat0_1 pat0_2
         *    0x000c:  pat0_3 pat0_4 pat0_5 pat0_6
         *    0x0010:  ena3   pat3_0 pat3_1 pat3_2
         *    0x0014:  pat3_3 pat3_4 pat3_5 pat3_6
         *    0x0018:  ena2   pat2_0 pat2_1 pat2_2
         *    0x001c:  pat2_3 pat2_4 pat2_5 pat2_6 */
        if(j % 2)
        {
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, tas.tas_thbuf[(j-1) * 2]),
                wol_pat.as_u32.high);
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, tas.tas_thbuf[(j-1) * 2 + 1]),
                wol_pat.as_u32.low);
        }
        else
        {
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, tas.tas_thbuf[(j+1) * 2]),
                wol_pat.as_u32.high);
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, tas.tas_thbuf[(j+1) * 2 + 1]),
                wol_pat.as_u32.low);
        }
    }

    for(idx = 0; idx < LM_MAX_NWUF_CNT; idx++)
    {
        nwuf = &nwuf_list->nwuf_arr[idx];
        nwuf->size = nwuf_size[idx];
    }

    return pattern_cnt;
} /* init_nwuf_5706 */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
init_nwuf(
    lm_device_t *pdev,
    lm_nwuf_list_t *nwuf_list)
{
    u32_t nwuf_cnt;

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        nwuf_cnt = init_nwuf_5706(pdev, nwuf_list);
    }
    else
    {
        nwuf_cnt = init_nwuf_5709(pdev, nwuf_list);
    }

    return nwuf_cnt;
} /* init_nwuf */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
set_d0_power_state(
    lm_device_t *pdev,
    u8_t set_pci_pm)
{
    u32_t val;
    u32_t idx;

    /* This step should be done by the OS or the caller.  Windows is
     * already doing this. */
    if(set_pci_pm)
    {
        /* Set the device to D0 state.  If a device is already in D3 state,
         * we will not be able to read the PCICFG_PM_CSR register using the
         * PCI memory command, we need to use config access here. */
        (void) mm_read_pci(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_pm_csr),
            &val);

        /* Set the device to D0 state.  This may be already done by the OS. */
        val &= ~PCICFG_PM_CSR_STATE;
        val |= PCICFG_PM_CSR_STATE_D0 | PCICFG_PM_CSR_PME_STATUS;

        (void) mm_write_pci(
            pdev,
            OFFSETOF(reg_space_t, pci_config.pcicfg_pm_csr),
            val);
    }

    /* With 5706_A1, the chip gets a reset coming out of D3.  Wait
     * for the boot to code finish running before we continue.  Without
     * this wait, we could run into lockup or the PHY may not work. */
    if(CHIP_ID(pdev) == CHIP_ID_5706_A1)
    {
        for(idx = 0; idx < 1000; idx++)
        {
            mm_wait(pdev, 15);
        }
    }

    /* Clear the ACPI_RCVD and MPKT_RCVD bits and disable magic packet. */
    REG_RD(pdev, emac.emac_mode, &val);
    val |= EMAC_MODE_MPKT_RCVD | EMAC_MODE_ACPI_RCVD;
    val &= ~EMAC_MODE_MPKT;
    REG_WR(pdev, emac.emac_mode, val);

    /* Disable interesting packet detection. */
    REG_RD(pdev, rpm.rpm_config, &val);
    val &= ~RPM_CONFIG_ACPI_ENA;
    REG_WR(pdev, rpm.rpm_config, val);
} /* set_d0_power_state */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
set_d3_power_state(
    lm_device_t *pdev,
    lm_wake_up_mode_t wake_up_mode,
    u8_t set_pci_pm)
{
    u32_t fw_timed_out;
    u32_t reset_reason;
    u32_t gpio_pin;
    u32_t val;
    u32_t cnt;

    /* Set up magic and interesting packet detection. */
    if(wake_up_mode & (LM_WAKE_UP_MODE_MAGIC_PACKET | LM_WAKE_UP_MODE_NWUF))
    {
        /* Enable magic packet detection. */
        REG_RD(pdev, emac.emac_mode, &val);
        if(wake_up_mode & LM_WAKE_UP_MODE_MAGIC_PACKET)
        {
            val |= EMAC_MODE_MPKT;
        }
        else
        {
            val &= ~EMAC_MODE_MPKT;
        }

        /* Enable port mode. */
        val &= ~EMAC_MODE_PORT;
        if(CHIP_REV(pdev) == CHIP_REV_FPGA || CHIP_REV(pdev) == CHIP_REV_IKOS)
        {
            /* IKOS or FPGA always run in GMII mode even if its actual
             * link speed is 10mb or 100mb. */
            val |= EMAC_MODE_PORT_GMII;
        }
        else
        {
            val |= EMAC_MODE_PORT_MII;
        }
        val |= EMAC_MODE_MPKT_RCVD | EMAC_MODE_ACPI_RCVD;

        REG_WR(pdev, emac.emac_mode, val);

        /* Set up the receive mask. */
        (void) lm_set_rx_mask(
            pdev,
            RX_FILTER_USER_IDX0,
            LM_RX_MASK_ACCEPT_UNICAST |
                LM_RX_MASK_ACCEPT_ALL_MULTICAST |
                LM_RX_MASK_ACCEPT_BROADCAST);

        /* The first four address slots are use for magic packet detection.
         * we need to initialize all four address slots. */
        for(cnt = 0; cnt < 4; cnt++)
        {
            (void) lm_set_mac_addr(pdev, cnt, pdev->params.mac_addr);
        }

        /* Need to enable EMAC and RPM for WOL. */
        REG_WR(
            pdev,
            misc.misc_enable_set_bits,
            MISC_ENABLE_SET_BITS_RX_PARSER_MAC_ENABLE |
                MISC_ENABLE_SET_BITS_TX_HEADER_Q_ENABLE |
                MISC_ENABLE_SET_BITS_EMAC_ENABLE);

        /* Enable interesting packet detection.  This must be done after
         * the necessary blocks are enabled, otherwise we may wake-up on
         * a bogus first packet.  Need to document this in prm. */
        REG_RD(pdev, rpm.rpm_config, &val);
        if(wake_up_mode & LM_WAKE_UP_MODE_NWUF)
        {
            REG_WR(pdev, rpm.rpm_config, val & ~RPM_CONFIG_ACPI_ENA);

            /* Also need to be documented in the prm - to prevent a false
             * detection, we need to disable ACP_EN if there is no pattern
             * programmed.  There is no way of preventing false detection
             * by intializing the pattern buffer a certain way. */
            if(init_nwuf(pdev, &pdev->nwuf_list))
            {
                val |= RPM_CONFIG_ACPI_ENA;
            }
            else
            {
                val &= ~RPM_CONFIG_ACPI_ENA;
            }
        }
        else
        {
            val &= ~RPM_CONFIG_ACPI_ENA;
        }
        REG_WR(pdev, rpm.rpm_config, val);

        /* xinan requires rbuf to be enabled.  enabling it for teton
         * does not hurt. */
        REG_WR(
            pdev,
            misc.misc_enable_set_bits,
            MISC_ENABLE_SET_BITS_RX_MBUF_ENABLE);

        reset_reason = LM_REASON_WOL_SUSPEND;
    }
    else
    {
        reset_reason = LM_REASON_NO_WOL_SUSPEND;
    }

    /* Allow the firmware to make any final changes to the chip before
     * we go into D3 mode.  The timeout period is longer because the
     * firwmare could take more time to download management firmware
     * which occurs during this stage of the reset. */
    fw_timed_out = fw_reset_sync(
        pdev,
        reset_reason,
        DRV_MSG_DATA_WAIT3,
        FW_ACK_TIME_OUT_MS*1000 * 3);

    /* If the firmware is not running, we have to switch to vaux power,
     * otherwise let the firmware do it. */
    if(fw_timed_out)
    {
        /* Power down the PHY. */
        if(pdev->params.enable_remote_phy == FALSE)
        {
            if(CHIP_REV(pdev) != CHIP_REV_FPGA &&
                CHIP_REV(pdev) != CHIP_REV_IKOS)
            {
                (void) lm_mwrite(
                    pdev,
                    pdev->params.phy_addr,
                    0x1c,
                    0xa821);
            }
        }

        /* Minimum core clock for a particular link.
         *    10Mb      core_clk = 6.25Mhz
         *    100Mb     core_clk = 12Mhz
         *    1Gb       core_clk = 100Mhz (use PLL)
         *
         * The driver is configured to autoneg to 10/100Mb for WOL mode.  So
         * the core clock needs to be configured to 12Mhz. */
        REG_RD(pdev, misc.misc_clock_control_bits, &val);
        val &= ~(MISC_CLOCK_CONTROL_BITS_CORE_CLK_DISABLE |
            MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT |
            MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_TE);

        /* Select the 12.5m alt clock. */
        REG_WR(
            pdev,
            misc.misc_clock_control_bits,
            MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_12_TE | val);

        /* Switch to the alt clock. */
        REG_WR(
            pdev,
            misc.misc_clock_control_bits,
            MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_12_TE |
                MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT |
                val);

        /* Disable core clock to non-wol blocks. */
        REG_WR(
            pdev,
            misc.misc_clock_control_bits,
            MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_12_TE |
                MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT |
                MISC_CLOCK_CONTROL_BITS_CORE_CLK_DISABLE |
                val);

        gpio_pin = 1 << 2;  /* GPIO 2 */

        /* Switch to vaux power by bring GPIO2 to low. */
        REG_RD(pdev, misc.misc_spio, &val);
        val &= ~(gpio_pin << 24);           /* use this gpio as output. */
        val |= gpio_pin << 16;              /* clear the gpio. */
        REG_WR(pdev, misc.misc_spio, val);

        /* This step should be done by the OS or the caller.  Windows is
         * already doing this. */
        if(set_pci_pm)
        {
            /* Set the device to D3 state. */
            REG_RD_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_pm_csr),
                &val);

            val &= ~PCICFG_PM_CSR_STATE;
            val |= PCICFG_PM_CSR_STATE_D3_HOT;

            REG_WR_OFFSET(
                pdev,
                OFFSETOF(reg_space_t, pci_config.pcicfg_pm_csr),
                val);
        }
    }
} /* set_d3_power_state */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_set_power_state(
    lm_device_t *pdev,
    lm_power_state_t power_state,
    lm_wake_up_mode_t wake_up_mode,     /* Valid when power_state is D3. */
    u8_t set_pci_pm)
{
    if(power_state == LM_POWER_STATE_D0)
    {
        set_d0_power_state(pdev, set_pci_pm);
    }
    else
    {
        set_d3_power_state(pdev, wake_up_mode, set_pci_pm);
    }
} /* lm_set_power_state */



#ifndef EXCLUDE_KQE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_submit_kernel_wqes(
    lm_device_t *pdev,
    kwqe_t *wqes[],
    u32_t num_wqes)
{
    kwqe_t *prod_qe;
    u16_t prod_idx;
    u32_t qe_cnt;

    if(num_wqes > pdev->kq_info.kwqe_left)
    {
        pdev->kq_info.no_kwq_bd_left++;

        return 0;
    }

    pdev->kq_info.kwqe_left -= num_wqes;

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    qe_cnt = num_wqes;
    while(qe_cnt)
    {
        *prod_qe = *(*wqes);

        if(prod_qe == pdev->kq_info.kwq_last_qe)
        {
            prod_qe = pdev->kq_info.kwq_virt;
        }
        else
        {
            prod_qe++;
        }

        wqes++;
        prod_idx++;
        qe_cnt--;
    }

    pdev->kq_info.kwq_prod_qe = prod_qe;
    pdev->kq_info.kwq_prod_idx = prod_idx;

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);

    return num_wqes;
} /* lm_submit_kernel_wqes */
#endif /* EXCLUDE_KQE_SUPPORT */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_interrupt_status_t
lm_get_interrupt_status(
    lm_device_t *pdev)
{
    lm_interrupt_status_t intr_status;
    u32_t deasserted_attns;
    u32_t asserted_attns;
    lm_rx_chain_t *rxq;
    lm_tx_chain_t *txq;
    u16_t hw_con_idx;
    u32_t val;
    u32_t idx;

    intr_status = LM_NO_EVENT_ACTIVE;

    /* Determine link change status. */
    if(pdev->params.link_chng_mode == LINK_CHNG_MODE_USE_STATUS_REG)
    {
        REG_RD(pdev, emac.emac_status, &val);
        if(pdev->params.phy_int_mode == PHY_INT_MODE_MI_INTERRUPT)
        {
            if(val & EMAC_STATUS_MI_INT)
            {
                intr_status |= LM_PHY_EVENT_ACTIVE;
            }
        }
        else if(val & EMAC_STATUS_LINK_CHANGE)
        {
            intr_status |= LM_PHY_EVENT_ACTIVE;
        }

        GET_ATTN_CHNG_BITS(pdev, &asserted_attns, &deasserted_attns);
    }
    else
    {
        GET_ATTN_CHNG_BITS(pdev, &asserted_attns, &deasserted_attns);

        if(asserted_attns & STATUS_ATTN_BITS_LINK_STATE)
        {
            intr_status |= LM_PHY_EVENT_ACTIVE;
        }
        else if(deasserted_attns & STATUS_ATTN_BITS_LINK_STATE)
        {
            intr_status |= LM_PHY_EVENT_ACTIVE;
        }
    }

    /* Get driver pulse event.  MCP uses the TIMER_ABORT attention to
     * signal to the driver to write a driver pulse to the firmware. */
    if((asserted_attns & STATUS_ATTN_BITS_TIMER_ABORT) ||
        (deasserted_attns & STATUS_ATTN_BITS_TIMER_ABORT))
    {
        if(pdev->params.enable_remote_phy)
        {
            REG_RD_IND(
                pdev,
                pdev->hw_info.shmem_base +
                    OFFSETOF(shmem_region_t, fw_evt_mb.fw_evt_code_mb),
                &val);

            if(val == 0)
            {
                intr_status |= LM_KNOCK_KNOCK_EVENT;
            }
            else if(val == FW_EVT_CODE_LINK_STATUS_CHANGE_EVENT)
            {
                intr_status |= LM_PHY_EVENT_ACTIVE;
            }
            else
            {
                DbgBreakMsg("not a valid fw event.\n");
            }
        }
        else
        {
            intr_status |= LM_KNOCK_KNOCK_EVENT;
        }

        if(asserted_attns & STATUS_ATTN_BITS_TIMER_ABORT)
        {
            REG_WR(
                pdev,
                pci_config.pcicfg_status_bit_set_cmd,
                asserted_attns & STATUS_ATTN_BITS_TIMER_ABORT);
        }
        else
        {
            REG_WR(
                pdev,
                pci_config.pcicfg_status_bit_clear_cmd,
                deasserted_attns & STATUS_ATTN_BITS_TIMER_ABORT);
        }
    }

    /* get l2 tx events. */
    for(idx = 0; idx < pdev->tx_info.num_txq; idx++)
    {
        txq = &pdev->tx_info.chain[idx];

        hw_con_idx = *txq->hw_con_idx_ptr;
        if((hw_con_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
        {
            hw_con_idx++;
        }

        if(hw_con_idx != txq->con_idx)
        {
            intr_status |= LM_TX0_EVENT_ACTIVE << txq->idx;
        }
    }

    /* get l2 rx events. */
    for(idx = 0; idx < pdev->rx_info.num_rxq; idx++)
    {
        rxq = &pdev->rx_info.chain[idx];

        hw_con_idx = *rxq->hw_con_idx_ptr;
        if((hw_con_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
        {
            hw_con_idx++;
        }

        if(hw_con_idx != rxq->con_idx)
        {
            intr_status |= LM_RX0_EVENT_ACTIVE << rxq->idx;
        }
    }

    #ifndef EXCLUDE_KQE_SUPPORT
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        /* HC install problem:  as a workaround, rx_quick_consumer_index15
         * is high jacked for use as cmd_con_idx.  The original cmd_con_idx
         * is not used. */
        if(pdev->kq_info.kwq_con_idx !=
            pdev->vars.status_virt->deflt.status_rx_quick_consumer_index15)
        {
            intr_status |= LM_KWQ_EVENT_ACTIVE;
        }
    }
    else
    {
        if(pdev->kq_info.kwq_con_idx !=
            pdev->vars.status_virt->deflt.status_cmd_consumer_index)
        {
            intr_status |= LM_KWQ_EVENT_ACTIVE;
        }
    }

    if(pdev->kq_info.kcq_con_idx !=
        pdev->vars.status_virt->deflt.status_completion_producer_index)
    {
        intr_status |= LM_KCQ_EVENT_ACTIVE;
    }
    #endif

    #if INCLUDE_OFLD_SUPPORT
    else if(pdev->params.hcopy_desc_cnt)
    {
        if(pdev->ofld.hcopy_chain.con_idx !=
            *(pdev->ofld.hcopy_chain.hw_con_idx_ptr))
        {
            intr_status |= LM_KCQ_EVENT_ACTIVE;
        }
    }
    #endif

    return intr_status;
} /* lm_get_interrupt_status */



#ifndef EXCLUDE_KQE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_ack_completed_wqes(
    lm_device_t *pdev)
{
    u16_t new_con_idx;
    kwqe_t *con_qe;
    u16_t num_wqes;
    u16_t con_idx;

    /* HC install problem:  as a workaround, rx_quick_consumer_index15
     * is high jacked for use as cmd_con_idx.  The original cmd_con_idx
     * is not used. */
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        new_con_idx =
            pdev->vars.status_virt->deflt.status_rx_quick_consumer_index15;
    }
    else
    {
        new_con_idx = pdev->vars.status_virt->deflt.status_cmd_consumer_index;
    }

    num_wqes = (u16_t) S16_SUB(new_con_idx, pdev->kq_info.kwq_con_idx);
    pdev->kq_info.kwqe_left += num_wqes;

    con_idx = new_con_idx;
    con_qe = pdev->kq_info.kwq_con_qe + num_wqes;

    /* Check for con_qe wrap around. */
    if((u8_t *) con_qe > (u8_t *) pdev->kq_info.kwq_last_qe)
    {
        con_qe = (kwqe_t *) ((u8_t *) pdev->kq_info.kwq_virt +
            ((u8_t *) con_qe - (u8_t *) pdev->kq_info.kwq_last_qe));
        con_qe--;
    }

    pdev->kq_info.kwq_con_idx = con_idx;
    pdev->kq_info.kwq_con_qe = con_qe;

    /* Make sure the con_qe and con_idx are consistent. */
    DbgBreakIf(((((u8_t *) con_qe - (u8_t *) pdev->kq_info.kwq_virt) /
        sizeof(kwqe_t)) & 0x7f) != (con_idx & 0x7f));

    #if DBG
    /* Make sure all the kwqes are accounted for. */
    if(S16_SUB(pdev->kq_info.kwq_prod_idx, con_idx) >= 0)
    {
        num_wqes = pdev->kq_info.kwqe_left +
            (u32_t) S16_SUB(pdev->kq_info.kwq_prod_idx, con_idx);
    }
    else
    {
        num_wqes = pdev->kq_info.kwqe_left + 0x10000 - con_idx +
            pdev->kq_info.kwq_prod_idx;
    }

    DbgBreakIf(num_wqes != (LM_PAGE_SIZE/sizeof(kwqe_t)) *
        pdev->params.kwq_page_cnt - 1);
    #endif
} /* lm_ack_completed_wqes */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_get_kernel_cqes(
    lm_device_t *pdev,
    kcqe_t *cqe_ptr[],
    u32_t ptr_cnt)
{
    kcqe_t *con_qe;
    u16_t prod_idx;
    u32_t num_cqes;
    u16_t con_idx;

    DbgMessage(pdev, VERBOSEint, "### lm_get_kernel_cqes\n");

    con_idx = pdev->kq_info.kcq_con_idx;
    con_qe = pdev->kq_info.kcq_con_qe;

    DbgBreakIf(((((u8_t *) con_qe - (u8_t *) pdev->kq_info.kcq_virt) /
        sizeof(kcqe_t)) & 0x7f) != (con_idx & 0x7f));

    num_cqes = 0;
    prod_idx = pdev->vars.status_virt->deflt.status_completion_producer_index;

    while(con_idx != prod_idx && num_cqes != ptr_cnt)
    {
        *cqe_ptr = con_qe;
        cqe_ptr++;
        num_cqes++;
        con_idx++;

        if(con_qe == pdev->kq_info.kcq_last_qe)
        {
            con_qe = pdev->kq_info.kcq_virt;
        }
        else
        {
            con_qe++;
        }

        prod_idx =
            pdev->vars.status_virt->deflt.status_completion_producer_index;
    }

    /* Make sure the last entry in the array does not have the 'next'
     * bit set.  We want to ensure the array contains all the cqes
     * for a completion.
     *
     * This piece of code also takes care of the case where a completion
     * spans multiple kcqes and not all the kcqes have been dma'd to
     * the host.  For example, if a completion consists of A, B, C, and D
     * kcqes.  The status block may tell us A and B have been dma'd.  In
     * this case, we don't want to return kcqes A and B in the array. */
    cqe_ptr--;
    while(num_cqes && ((*cqe_ptr)->kcqe_flags & KCQE_FLAGS_NEXT))
    {
        num_cqes--;
        cqe_ptr--;
    }

    DbgBreakIf(num_cqes == 0);

    return num_cqes;
} /* lm_get_kernel_cqes */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u8_t
lm_ack_kernel_cqes(
    lm_device_t *pdev,
    u32_t num_cqes)
{
    kcqe_t *con_qe;
    u16_t prod_idx;
    u16_t con_idx;

    DbgMessage(pdev, VERBOSEint, "### lm_ack_kernel_cqes\n");

    con_idx = pdev->kq_info.kcq_con_idx;

    if(num_cqes)
    {
        /* Advance the consumer index and the con_qe pointer */
        con_idx += (u16_t) num_cqes;
        con_qe = pdev->kq_info.kcq_con_qe + num_cqes;

        /* Check for con_qe wrap around. */
        if((u8_t *) con_qe > (u8_t *) pdev->kq_info.kcq_last_qe)
        {
            con_qe = (kcqe_t *) ((u8_t *) pdev->kq_info.kcq_virt +
                ((u8_t *) con_qe - (u8_t *) pdev->kq_info.kcq_last_qe));
            con_qe--;
        }

        pdev->kq_info.kcq_con_idx = con_idx;
        pdev->kq_info.kcq_con_qe = con_qe;

        /* Don't acknowledge the last 'kcq_history_size' entries so the
         * chip will not over write them with new entries.  We are doing
         * this to have a history of the kcq entries for debugging. */
        if(pdev->params.kcq_history_size)
        {
            /* The con_idx should always be ahead of history_kcq_con_idx. */
            DbgBreakIf(S16_SUB(con_idx, pdev->kq_info.history_kcq_con_idx) < 0);

            /* Number of entries between con_idx and history_kcq_con_idx. */
            num_cqes = (u32_t) S16_SUB(
                con_idx,
                pdev->kq_info.history_kcq_con_idx);

            /* Don't advance the consumer index if the number of history
             * entries is less than 'kcq_history_size'. */
            if(num_cqes >= pdev->params.kcq_history_size)
            {
                /* Make sure we will have at most kcq_history_size entires. */
                num_cqes -= pdev->params.kcq_history_size;

                DbgBreakIf(num_cqes > pdev->params.kcq_history_size);

                /* Advance the consumer index and the con_qe pointer */
                pdev->kq_info.history_kcq_con_idx += (u16_t) num_cqes;
                con_qe = pdev->kq_info.history_kcq_con_qe + num_cqes;

                /* Check for con_qe wrap around. */
                if((u8_t *) con_qe > (u8_t *) pdev->kq_info.kcq_last_qe)
                {
                    con_qe = (kcqe_t *) ((u8_t *) pdev->kq_info.kcq_virt +
                        ((u8_t *) con_qe -
                         (u8_t *) pdev->kq_info.kcq_last_qe));
                    con_qe--;
                }
                pdev->kq_info.history_kcq_con_qe = con_qe;

                MBQ_WR16(
                    pdev,
                    GET_CID(pdev->kq_info.kcq_cid_addr),
                    OFFSETOF(krnlq_context_t, krnlq_host_qidx),
                    pdev->kq_info.history_kcq_con_idx);
            }
        }
        else
        {
            MBQ_WR16(
                pdev,
                GET_CID(pdev->kq_info.kcq_cid_addr),
                OFFSETOF(krnlq_context_t, krnlq_host_qidx),
                con_idx);
        }
    }

    prod_idx = pdev->vars.status_virt->deflt.status_completion_producer_index;

    DbgBreakIf(S16_SUB(prod_idx, con_idx) < 0);

    return con_idx != prod_idx;
} /* lm_ack_kernel_cqes */
#endif /* EXCLUDE_KQE_SUPPORT */



#ifndef EXCLUDE_RSS_SUPPORT
#if RSS_LOOKUP_TABLE_WA
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u64_t
rss_f64(
    u8_t* key,
    u8_t s,
    u8_t e
    )
{
    u64_t f;

    for( f=0; s<=e; ++s )
    {
        f = (f << 8);
        f |= key[s];
    }

    return f;
}



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
rss_hash_byte(
    u8_t* key,
    u8_t  byte,
    u8_t  s,
    u8_t  e,
    u32_t rst
    )
{
    u8_t i;
    u64_t key_msb;

    key_msb = rss_f64(key, s,e);

    for( i=0x80; i!=0; i>>=1 )
    {
        if( i & byte )
        {
            u32_t k;

            k = (u32_t)(key_msb >> 32);
            rst ^= k;
        }
        key_msb = (key_msb << 1);
    }

    return rst;
}



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
rss_gen_one_table(
    u8_t* key,
    u8_t  s,
    u8_t  e,
    u32_t* gtbl
    )
{
    u32_t i;

    for( i = 0; i < 256; ++i )
    {
        gtbl[i] = rss_hash_byte( key, (u8_t)i, s, e, 0 );
    }
}



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
rss_gen_tables(
    u8_t* key,
    u32_t* tables
    )
{
    u8_t t;

    for( t = 0; t < 12; ++t )
    {
        rss_gen_one_table( key, t, (u8_t)(t+7), tables );
        tables += 256;
    }
}
#endif


#ifndef LM_NON_LEGACY_MODE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_enable_rss(
    lm_device_t *pdev,
    lm_rss_hash_t hash_type,
    u8_t *indirection_table,
    u32_t table_size,
    u8_t *hash_key,
    u32_t key_size)
{
    l2_kwqe_rss_table_update_t *rss_update;
    u8_t rss_key[RSS_HASH_KEY_SIZE];
    lm_address_t rss_table_phy;
    u8_t *rss_table_virt;
    kwqe_t *prod_qe;
    u16_t prod_idx;
    u32_t idx;
    u32_t val;

    if(pdev->kq_info.kwqe_left < 2)
    {
        pdev->kq_info.no_kwq_bd_left++;
        return LM_STATUS_RESOURCE;
    }

    pdev->kq_info.kwqe_left -= 2;

    DbgBreakIf(key_size > RSS_HASH_KEY_SIZE);

    /* Initialize the rss key array. */
    if(key_size > RSS_HASH_KEY_SIZE)
    {
        key_size = RSS_HASH_KEY_SIZE;
    }

    for(idx = 0; idx < key_size; idx++)
    {
        rss_key[idx] = hash_key[idx];
    }

    for(idx = key_size; idx < RSS_HASH_KEY_SIZE; idx++)
    {
        rss_key[idx] = 0;
    }

    DbgBreakIf(table_size > RSS_INDIRECTION_TABLE_SIZE);

    if(table_size > RSS_INDIRECTION_TABLE_SIZE)
    {
        table_size = RSS_INDIRECTION_TABLE_SIZE;
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, rlup.rlup_rss_config, &val);
        val &= ~RLUP_RSS_CONFIG_IPV4_RSS_TYPE_OFF_XI;
        val &= ~RLUP_RSS_CONFIG_IPV6_RSS_TYPE_OFF_XI;
        REG_WR(pdev, rlup.rlup_rss_config, val);

        val = (rss_key[0] << 24) |
              (rss_key[1] << 16) |
              (rss_key[2] << 8) |
               rss_key[3];
        REG_WR(pdev, rlup.rlup_rss_key1, val);

        val = (rss_key[4] << 24) |
              (rss_key[5] << 16) |
              (rss_key[6] << 8) |
               rss_key[7];
        REG_WR(pdev, rlup.rlup_rss_key2, val);

        val = (rss_key[8] << 24) |
              (rss_key[9] << 16) |
              (rss_key[10] << 8) |
               rss_key[11];
        REG_WR(pdev, rlup.rlup_rss_key3, val);

        val = (rss_key[12] << 24) |
              (rss_key[13] << 16) |
              (rss_key[14] << 8) |
               rss_key[15];
        REG_WR(pdev, rlup.rlup_rss_key4, val);

        val = (rss_key[16] << 24) |
              (rss_key[17] << 16) |
              (rss_key[18] << 8) |
               rss_key[19];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key5, val);

        val = (rss_key[20] << 24) |
              (rss_key[21] << 16) |
              (rss_key[22] << 8) |
               rss_key[23];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key6, val);

        val = (rss_key[24] << 24) |
              (rss_key[25] << 16) |
              (rss_key[26] << 8) |
               rss_key[27];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key7, val);

        val = (rss_key[28] << 24) |
              (rss_key[29] << 16) |
              (rss_key[30] << 8) |
               rss_key[31];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key8, val);

        val = (rss_key[32] << 24) |
              (rss_key[33] << 16) |
              (rss_key[34] << 8) |
               rss_key[35];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key9, val);

        val = (rss_key[36] << 24) |
              (rss_key[37] << 16) |
              (rss_key[38] << 8) |
               rss_key[39];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key10, val);
    }

    rss_table_virt = pdev->rx_info.rss_ind_table_virt;
    rss_table_phy = pdev->rx_info.rss_ind_table_phy;

    for(idx = 0; idx < table_size; idx++)
    {
        rss_table_virt[idx] = indirection_table[idx];
    }

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    /* Initialize the RSS update KWQE. */
    rss_update = (l2_kwqe_rss_table_update_t *) prod_qe;

    rss_update->rss_flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
    rss_update->rss_opcode = L2_KWQE_OPCODE_VALUE_UPDATE_RSS;

    rss_update->rss_table_size = (u16_t) table_size;
    rss_update->rss_table_haddr_lo = rss_table_phy.as_u32.low;
    rss_update->rss_table_haddr_hi = rss_table_phy.as_u32.high;
    rss_update->rss_host_opaque = 0;
    rss_update->rss_hash_type = hash_type;

    #if RSS_LOOKUP_TABLE_WA
    rss_table_virt += RSS_INDIRECTION_TABLE_SIZE;
    LM_INC64(&rss_table_phy, RSS_INDIRECTION_TABLE_SIZE);

    rss_update->rss_lookup_table_lo = rss_table_phy.as_u32.low;
    rss_update->rss_lookup_table_hi = rss_table_phy.as_u32.high;

    rss_gen_tables(rss_key, (u32_t *) rss_table_virt);
    #endif

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

    /* Initialize the RSS enable KWQE. */
    rss_update = (l2_kwqe_rss_table_update_t *) prod_qe;

    rss_update->rss_flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
    rss_update->rss_opcode = L2_KWQE_OPCODE_VALUE_ENABLE_RSS;
    rss_update->rss_host_opaque = 0;
    rss_update->rss_hash_type = hash_type;

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

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);

    return LM_STATUS_SUCCESS;
} /* lm_enable_rss */
#else /* LM_LEAGCY_MODE_SUPPORT */
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_enable_rss(
    lm_device_t *pdev,
    lm_rss_hash_t hash_type,
    PROCESSOR_NUMBER *indirection_table,
    u32_t table_size,
    u8_t *hash_key,
    u32_t key_size,
    u8_t *cpu_tbl,
    u8_t *rss_qidx_tbl)
{
    l2_kwqe_rss_table_update_t *rss_update;
    u8_t rss_key[RSS_HASH_KEY_SIZE];
    lm_address_t rss_table_phy;
    u8_t *rss_table_virt;
    kwqe_t *prod_qe;
    u16_t prod_idx;
    u32_t idx;
    u32_t val;

    if(pdev->kq_info.kwqe_left < 2)
    {
        pdev->kq_info.no_kwq_bd_left++;
        return LM_STATUS_RESOURCE;
    }

    pdev->kq_info.kwqe_left -= 2;

    DbgBreakIf(key_size > RSS_HASH_KEY_SIZE);

    /* Initialize the rss key array. */
    if(key_size > RSS_HASH_KEY_SIZE)
    {
        key_size = RSS_HASH_KEY_SIZE;
    }

    for(idx = 0; idx < key_size; idx++)
    {
        rss_key[idx] = hash_key[idx];
    }

    for(idx = key_size; idx < RSS_HASH_KEY_SIZE; idx++)
    {
        rss_key[idx] = 0;
    }

    DbgBreakIf(table_size > RSS_INDIRECTION_TABLE_SIZE);

    if(table_size > RSS_INDIRECTION_TABLE_SIZE)
    {
        table_size = RSS_INDIRECTION_TABLE_SIZE;
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, rlup.rlup_rss_config, &val);
        val &= ~RLUP_RSS_CONFIG_IPV4_RSS_TYPE_OFF_XI;
        val &= ~RLUP_RSS_CONFIG_IPV6_RSS_TYPE_OFF_XI;
        REG_WR(pdev, rlup.rlup_rss_config, val);

        val = (rss_key[0] << 24) |
              (rss_key[1] << 16) |
              (rss_key[2] << 8) |
               rss_key[3];
        REG_WR(pdev, rlup.rlup_rss_key1, val);

        val = (rss_key[4] << 24) |
              (rss_key[5] << 16) |
              (rss_key[6] << 8) |
               rss_key[7];
        REG_WR(pdev, rlup.rlup_rss_key2, val);

        val = (rss_key[8] << 24) |
              (rss_key[9] << 16) |
              (rss_key[10] << 8) |
               rss_key[11];
        REG_WR(pdev, rlup.rlup_rss_key3, val);

        val = (rss_key[12] << 24) |
              (rss_key[13] << 16) |
              (rss_key[14] << 8) |
               rss_key[15];
        REG_WR(pdev, rlup.rlup_rss_key4, val);

        val = (rss_key[16] << 24) |
              (rss_key[17] << 16) |
              (rss_key[18] << 8) |
               rss_key[19];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key5, val);

        val = (rss_key[20] << 24) |
              (rss_key[21] << 16) |
              (rss_key[22] << 8) |
               rss_key[23];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key6, val);

        val = (rss_key[24] << 24) |
              (rss_key[25] << 16) |
              (rss_key[26] << 8) |
               rss_key[27];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key7, val);

        val = (rss_key[28] << 24) |
              (rss_key[29] << 16) |
              (rss_key[30] << 8) |
               rss_key[31];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key8, val);

        val = (rss_key[32] << 24) |
              (rss_key[33] << 16) |
              (rss_key[34] << 8) |
               rss_key[35];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key9, val);

        val = (rss_key[36] << 24) |
              (rss_key[37] << 16) |
              (rss_key[38] << 8) |
               rss_key[39];
        REG_WR(pdev, rlup.rlup_ipv6_rss_key10, val);
    }

    rss_table_virt = pdev->rx_info.rss_ind_table_virt;
    rss_table_phy = pdev->rx_info.rss_ind_table_phy;

    pdev->rx_info.rss_tbl_size = table_size;
    if(!cpu_tbl) /* indirection table already had queue idx? */
    {
        for(idx = 0; idx < table_size; idx++)
            rss_table_virt[idx] = indirection_table[idx].Number;
    }
    else
    {
        /* map the cpu num in the indirection table to queue idx
         * according to the cpu table passed down from the um, then
         * rebuilt the table with queue idx*/
        u8_t *rss_cpu_tbl = &cpu_tbl[1];

        for(idx = 0; idx < table_size; idx++)
        {
            for(val = 0; val < cpu_tbl[0]; val++)
            {
                if(indirection_table[idx].Number == rss_cpu_tbl[val])
                {
                    if(pdev->vars.interrupt_mode == IRQ_MODE_MSIX_BASED ||
                       pdev->vars.interrupt_mode == IRQ_MODE_MSI_BASED)
                    {
                        rss_table_virt[idx] = rss_qidx_tbl[rss_cpu_tbl[val] + 1];
                    }
                    else
                    {
                        rss_table_virt[idx] = (u8_t)val;
                    }
                    break;
                }
            }
        }
    }

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    /* Initialize the RSS update KWQE. */
    rss_update = (l2_kwqe_rss_table_update_t *) prod_qe;

    rss_update->rss_flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
    rss_update->rss_opcode = L2_KWQE_OPCODE_VALUE_UPDATE_RSS;

    rss_update->rss_table_size = (u16_t) table_size;
    rss_update->rss_table_haddr_lo = rss_table_phy.as_u32.low;
    rss_update->rss_table_haddr_hi = rss_table_phy.as_u32.high;
    rss_update->rss_host_opaque = 0;
    rss_update->rss_hash_type = hash_type;

    #if RSS_LOOKUP_TABLE_WA
    rss_table_virt += RSS_INDIRECTION_TABLE_SIZE;
    LM_INC64(&rss_table_phy, RSS_INDIRECTION_TABLE_SIZE);

    rss_update->rss_lookup_table_lo = rss_table_phy.as_u32.low;
    rss_update->rss_lookup_table_hi = rss_table_phy.as_u32.high;

    rss_gen_tables(rss_key, (u32_t *) rss_table_virt);
    #endif

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

    /* Initialize the RSS enable KWQE. */
    rss_update = (l2_kwqe_rss_table_update_t *) prod_qe;

    rss_update->rss_flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
    rss_update->rss_opcode = L2_KWQE_OPCODE_VALUE_ENABLE_RSS;
    rss_update->rss_host_opaque = 0;
    rss_update->rss_hash_type = hash_type;

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

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);

    return LM_STATUS_SUCCESS;
} /* lm_enable_rss */
#endif /* LM_NON_LEGACY_MODE_SUPPORT */


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_disable_rss(
    lm_device_t *pdev)
{
    l2_kwqe_rss_table_update_t *rss_update;
    kwqe_t *prod_qe;
    u16_t prod_idx;
    u32_t val;

    if(pdev->kq_info.kwqe_left < 1)
    {
        pdev->kq_info.no_kwq_bd_left++;
        return LM_STATUS_RESOURCE;
    }

    pdev->kq_info.kwqe_left -= 1;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, rlup.rlup_rss_config, &val);
        val &= ~RLUP_RSS_CONFIG_IPV4_RSS_TYPE_OFF_XI;
        val &= ~RLUP_RSS_CONFIG_IPV6_RSS_TYPE_OFF_XI;
        REG_WR(pdev, rlup.rlup_rss_config, val);
    }

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    /* Initialize the RSS enable KWQE. */
    rss_update = (l2_kwqe_rss_table_update_t *) prod_qe;

    rss_update->rss_flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
    rss_update->rss_opcode = L2_KWQE_OPCODE_VALUE_DISABLE_RSS;

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

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);

    return LM_STATUS_SUCCESS;
} /* lm_disable_rss */
#endif /* EXCLUDE_RSS_SUPPORT */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void lm_set_pcie_nfe_report(lm_device_t *pdev)
{
    if(CHIP_NUM(pdev) == CHIP_NUM_5709 &&
       pdev->params.disable_pcie_nfr)
    {
        u16_t pci_devctl;
        REG_RD(pdev,pci_config.pcicfg_device_control,&pci_devctl);
        pci_devctl &= ~PCICFG_DEVICE_CONTROL_NON_FATAL_REP_ENA;
        REG_WR(pdev,pci_config.pcicfg_device_control,pci_devctl);
    }
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void lm_clear_coalescing_ticks(lm_device_t *pdev)
{
    pdev->params.tx_quick_cons_trip = 1;
    pdev->params.tx_quick_cons_trip_int = 1;
    pdev->params.rx_quick_cons_trip = 1;
    pdev->params.rx_quick_cons_trip_int = 1;
    pdev->params.comp_prod_trip = 1;
    pdev->params.comp_prod_trip_int = 1;

    pdev->params.tx_ticks = 0;
    pdev->params.tx_ticks_int = 0;
    pdev->params.com_ticks = 0;
    pdev->params.com_ticks_int = 0;
    pdev->params.cmd_ticks = 0;
    pdev->params.cmd_ticks_int = 0;
    pdev->params.rx_ticks = 0;
    pdev->params.rx_ticks_int = 0;
    pdev->params.stats_ticks = 0;

    /* Xinan per-processor HC configuration. */
    pdev->params.psb_tx_cons_trip = 0x10001;
    pdev->params.psb_rx_cons_trip = 0x10001;
    pdev->params.psb_comp_prod_trip = 0x10001;

    pdev->params.psb_tx_ticks = 0;
    pdev->params.psb_rx_ticks = 0;
    pdev->params.psb_com_ticks = 0;
    pdev->params.psb_cmd_ticks = 0;
    pdev->params.psb_period_ticks = 0;
}

u8_t lm_is_mmio_ok(lm_device_t *pdev)
{
    u32_t val;
    REG_RD(pdev, pci_config.pcicfg_vendor_id, &val);
    if (0xffffffff == val)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

#if defined(LM_NON_LEGACY_MODE_SUPPORT)
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_create_q_group(
    lm_device_t *pdev,
    u32_t q_group_id,
    u32_t lookahead_sz
    )
{
    u32_t val;
    lm_rx_chain_t *rxq;

    rxq = &pdev->rx_info.chain[q_group_id];
    rxq->vmq_lookahead_size = lookahead_sz;

    val = lookahead_sz << 16;
    CTX_WR(
        pdev,
        rxq->cid_addr,
        WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t,
                              l2ctx_vmq_lookahead_sz),
        val);
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_destroy_q_group(
    lm_device_t *pdev,
    u32_t q_group_id,
    u32_t num_queues
    )
{
    u32_t num_kwqes_needed;
    kwqe_t *prod_qe;
    u16_t prod_idx;
    l2_kwqe_vm_free_rx_queue_t *kwqe_free_rxq;

    num_kwqes_needed = num_queues;

    if(pdev->kq_info.kwqe_left < num_kwqes_needed)
    {
        DbgMessage(pdev, WARN, "No more KWQE left.\n");

        pdev->kq_info.no_kwq_bd_left++;

        return LM_STATUS_RESOURCE;
    }

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    kwqe_free_rxq = (l2_kwqe_vm_free_rx_queue_t *) prod_qe;

    if(q_group_id <= RX_CHAIN_IDX3)
    {
        if(q_group_id == RX_CHAIN_IDX0)
        {
            u8_t idx;
            /* default queue may have more than 1 queue pairs */
            for(idx = 0; idx < num_queues; idx++)
            {
                kwqe_free_rxq->flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
                kwqe_free_rxq->queue_type = L2_NORMAL_QUEUE;

                if(idx == 0)
                    kwqe_free_rxq->qid = (u8_t)q_group_id;
                else
                {
                    kwqe_free_rxq->qid = idx + 3;
                }

                kwqe_free_rxq->opcode = L2_KWQE_OPCODE_VALUE_VM_FREE_RX_QUEUE;

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

                pdev->kq_info.kwqe_left -= 1;
                kwqe_free_rxq = (l2_kwqe_vm_free_rx_queue_t *) prod_qe;
            }
            pdev->kq_info.kwq_prod_qe = prod_qe;
            pdev->kq_info.kwq_prod_idx = prod_idx;

            MBQ_WR16(
                pdev,
                GET_CID(pdev->kq_info.kwq_cid_addr),
                OFFSETOF(krnlq_context_t, krnlq_host_qidx),
                prod_idx);

            return LM_STATUS_SUCCESS;
        }
        else
        {
            kwqe_free_rxq->queue_type = L2_NORMAL_QUEUE;
            kwqe_free_rxq->qid = (u8_t)q_group_id;
            pdev->kq_info.kwqe_left -= 1;
#if INCLUDE_OFLD_SUPPORT
            if(q_group_id == RX_CHAIN_IDX2 &&
               !s_list_is_empty(&pdev->rx_info.chain[RX_CHAIN_IDX1].active_descq))
            {
                kwqe_free_rxq->flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
                kwqe_free_rxq->opcode = L2_KWQE_OPCODE_VALUE_VM_FREE_RX_QUEUE;

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

                /* flush the catchup RX queue too */
                kwqe_free_rxq = (l2_kwqe_vm_free_rx_queue_t *) prod_qe;
                kwqe_free_rxq->queue_type = L2_NORMAL_QUEUE;
                kwqe_free_rxq->qid = (u8_t)RX_CHAIN_IDX1;
                pdev->kq_info.kwqe_left -= 1;
            }
#endif
        }
    }
    else
    {
        kwqe_free_rxq->queue_type = L2_VM_QUEUE;
        kwqe_free_rxq->qid = (u8_t)q_group_id;
        pdev->kq_info.kwqe_left -= 1;
    }
    kwqe_free_rxq->flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
    kwqe_free_rxq->opcode = L2_KWQE_OPCODE_VALUE_VM_FREE_RX_QUEUE;

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

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);

    return LM_STATUS_SUCCESS;
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
VOID
lm_update_defq_filter_ctx(
    lm_device_t *pdev,
    u8_t valid
    )
{
    u32_t ctx_offset = pdev->vars.hw_filter_ctx_offset;
    u32_t val = 0;

    if(valid)
        val |= L2_VM_FILTER_MAC << 16;

    REG_WR_IND(
        pdev,
        OFFSETOF(reg_space_t, rxp.rxp_scratch[0])+ctx_offset,
        val);
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_chng_q_group_filter(
    lm_device_t *pdev,
    u32_t q_group_id,
    u8_t  *dest_mac,
    u16_t *vlan_ptr,
    u32_t filter_id
    )
{
    kwqe_t *prod_qe;
    u16_t prod_idx;

    if(pdev->kq_info.kwqe_left < 1)
    {
        DbgMessage(pdev, WARN, "No more KWQE left.\n");

        pdev->kq_info.no_kwq_bd_left++;

        return LM_STATUS_RESOURCE;
    }

    prod_qe = pdev->kq_info.kwq_prod_qe;
    prod_idx = pdev->kq_info.kwq_prod_idx;

    pdev->kq_info.kwqe_left -= 1;
    if(dest_mac == NULL && vlan_ptr == NULL)
    {
        /* clear filter operation */
        l2_kwqe_vm_remove_rx_filter_t * kwqe_remove_rx_filter =
            (l2_kwqe_vm_remove_rx_filter_t *) prod_qe;
        kwqe_remove_rx_filter->flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
        kwqe_remove_rx_filter->qid = (u8_t)q_group_id;
        kwqe_remove_rx_filter->filter_id = (u8_t)filter_id;
        kwqe_remove_rx_filter->opcode = L2_KWQE_OPCODE_VALUE_VM_REMOVE_RX_FILTER;
    }
    else
    {
        /* set filter operation */
        l2_kwqe_vm_set_rx_filter_t * kwqe_set_rx_filter =
            (l2_kwqe_vm_set_rx_filter_t *) prod_qe;

        kwqe_set_rx_filter->flags = L2_KWQE_FLAGS_LAYER_MASK_L2;
        kwqe_set_rx_filter->qid = (u8_t)q_group_id;
        kwqe_set_rx_filter->filter_id = (u8_t)filter_id;
        if(vlan_ptr)
        {
            kwqe_set_rx_filter->vlan = *vlan_ptr;
            kwqe_set_rx_filter->filter_type = L2_VM_FILTER_MAC_VLAN;
        }
        else
        {
            kwqe_set_rx_filter->filter_type = L2_VM_FILTER_MAC;
        }
        kwqe_set_rx_filter->opcode = L2_KWQE_OPCODE_VALUE_VM_SET_RX_FILTER;
    }

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

    MBQ_WR16(
        pdev,
        GET_CID(pdev->kq_info.kwq_cid_addr),
        OFFSETOF(krnlq_context_t, krnlq_host_qidx),
        prod_idx);
    return LM_STATUS_PENDING;
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_service_l2_kcqes(
    struct _lm_device_t *pdev,
    kcqe_t *cqe_ptr[],
    u32_t num_cqes)
{
    u32_t cqe_serviced_cnt;
    u32_t cqe_cnt;
    u8_t success;
    kcqe_t *kcqe;
    lm_status_t lm_status;

    cqe_serviced_cnt = 0;
    while(num_cqes)
    {
        /* Determine the number of cqes for a completion.  Some
         * completions span several cqes. */
        cqe_cnt = 0;
        while(cqe_ptr[cqe_cnt]->kcqe_flags & KCQE_FLAGS_NEXT)
        {
            cqe_cnt++;
        }
        cqe_cnt++;

        DbgBreakIf(cqe_cnt > num_cqes);

        kcqe = *cqe_ptr;

        DbgBreakIf((kcqe->kcqe_flags & KCQE_FLAGS_LAYER_MASK) !=
                    KCQE_FLAGS_LAYER_MASK_L2);

        switch(kcqe->kcqe_opcode)
        {
            case L2_KCQE_OPCODE_VALUE_VM_FREE_RX_QUEUE:
                /* initiate rx buffer abort */
                {
                    l2_kcqe_vm_free_rx_queue_t *kcqe_free_rxq;

                    kcqe_free_rxq = (l2_kcqe_vm_free_rx_queue_t *)kcqe;
                    mm_q_grp_abort_rx_request(
                        pdev,
                        kcqe_free_rxq->qid);
                }
                break;

            case L2_KCQE_OPCODE_VALUE_VM_SET_RX_FILTER:
            case L2_KCQE_OPCODE_VALUE_VM_REMOVE_RX_FILTER:
                {
                    l2_kcqe_vm_set_rx_filter_t *kcqe_filter;

                    kcqe_filter = (l2_kcqe_vm_set_rx_filter_t *)kcqe;
                    if(kcqe_filter->status == SC_SUCCESS)
                    {
                        lm_status = LM_STATUS_SUCCESS;
                    }
                    else
                    {
                        lm_status = LM_STATUS_FAILURE;
                    }
                    mm_comp_l2_filter_chng_req(
                        pdev,
                        lm_status,
                        kcqe_filter->qid);
                }
                break;

            case L2_KCQE_OPCODE_VALUE_VM_ALLOC_RX_QUEUE:
            case L2_KCQE_OPCODE_VALUE_RX_PACKET:
            case L2_KCQE_OPCODE_VALUE_ENABLE_RSS:
            case L2_KCQE_OPCODE_VALUE_DISABLE_RSS:
            case L2_KCQE_OPCODE_VALUE_UPDATE_RSS:
            case L2_KCQE_OPCODE_VALUE_FLUSH_BD_CHAIN:
                /* no need to do anything in the driver */
                break;

            default:
                DbgBreakMsg("invalid l2 kcqe.\n");
                break;
        }

        cqe_ptr += cqe_cnt;
        num_cqes -= cqe_cnt;
        cqe_serviced_cnt += cqe_cnt;
    }

    return cqe_serviced_cnt;
}
#endif /* LM_NON_LEGACY_MODE_SUPPORT */
