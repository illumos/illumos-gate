/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2019 by Chelsio Communications, Inc.
 */

#ifndef __CUDBG_VIEW_H__
#define __CUDBG_VIEW_H__

#include "t4_hw.h"
#include "cudbg_lib_common.h"

#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
typedef boolean_t bool;
#endif

#define DECLARE_VIEW_FUNC(FOO)				\
	int view_##FOO(char *, struct cudbg_entity_hdr *, \
 		     struct cudbg_buffer *, enum chip_type);
DECLARE_VIEW_FUNC(cim_q);
DECLARE_VIEW_FUNC(cim_la);
DECLARE_VIEW_FUNC(reg_dump);
DECLARE_VIEW_FUNC(cim_qcfg);
DECLARE_VIEW_FUNC(mc0_data);
DECLARE_VIEW_FUNC(mc1_data);
DECLARE_VIEW_FUNC(fw_devlog);
DECLARE_VIEW_FUNC(cim_ma_la);
DECLARE_VIEW_FUNC(edc0_data);
DECLARE_VIEW_FUNC(edc1_data);
DECLARE_VIEW_FUNC(rss);
DECLARE_VIEW_FUNC(rss_pf_config);
DECLARE_VIEW_FUNC(rss_key);
DECLARE_VIEW_FUNC(rss_vf_config);
DECLARE_VIEW_FUNC(rss_config);
DECLARE_VIEW_FUNC(path_mtu);
DECLARE_VIEW_FUNC(sw_state);
DECLARE_VIEW_FUNC(wtp);
DECLARE_VIEW_FUNC(pm_stats);
DECLARE_VIEW_FUNC(tcp_stats);
DECLARE_VIEW_FUNC(hw_sched);
DECLARE_VIEW_FUNC(tp_err_stats_show);
DECLARE_VIEW_FUNC(fcoe_stats);
DECLARE_VIEW_FUNC(rdma_stats);
DECLARE_VIEW_FUNC(tp_indirect);
DECLARE_VIEW_FUNC(sge_indirect);
DECLARE_VIEW_FUNC(cpl_stats);
DECLARE_VIEW_FUNC(ddp_stats);
DECLARE_VIEW_FUNC(wc_stats);
DECLARE_VIEW_FUNC(ulprx_la);
DECLARE_VIEW_FUNC(lb_stats);
DECLARE_VIEW_FUNC(tp_la);
DECLARE_VIEW_FUNC(meminfo);
DECLARE_VIEW_FUNC(cim_pif_la);
DECLARE_VIEW_FUNC(clk_info);
DECLARE_VIEW_FUNC(macstats);
DECLARE_VIEW_FUNC(pcie_indirect);
DECLARE_VIEW_FUNC(pm_indirect);
DECLARE_VIEW_FUNC(full);
DECLARE_VIEW_FUNC(tx_rate);
DECLARE_VIEW_FUNC(tid);
DECLARE_VIEW_FUNC(pcie_config);
DECLARE_VIEW_FUNC(dump_context);
DECLARE_VIEW_FUNC(mps_tcam);
DECLARE_VIEW_FUNC(vpd_data);
DECLARE_VIEW_FUNC(le_tcam);
DECLARE_VIEW_FUNC(cctrl);
DECLARE_VIEW_FUNC(ma_indirect);
DECLARE_VIEW_FUNC(ulptx_la);
DECLARE_VIEW_FUNC(ext_entity);
DECLARE_VIEW_FUNC(up_cim_indirect);
DECLARE_VIEW_FUNC(pbt_tables);
DECLARE_VIEW_FUNC(mbox_log);
DECLARE_VIEW_FUNC(hma_indirect);
DECLARE_VIEW_FUNC(hma_data);
DECLARE_VIEW_FUNC(upload);
DECLARE_VIEW_FUNC(qdesc);

static int (*view_entity[]) (char *, struct cudbg_entity_hdr *,
			     struct cudbg_buffer *, enum chip_type) = {
	view_reg_dump,
	view_fw_devlog,
	view_cim_la,
	view_cim_ma_la,
	view_cim_qcfg,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_cim_q,
	view_edc0_data,
	view_edc1_data,
	view_mc0_data,
	view_mc1_data,
	view_rss,	    /*22*/
	view_rss_pf_config, /*23*/
	view_rss_key,	    /*24*/
	view_rss_vf_config,
	view_rss_config,
	view_path_mtu,
	view_sw_state,
	view_wtp,
	view_pm_stats,
	view_hw_sched,
	view_tcp_stats,
	view_tp_err_stats_show,
	view_fcoe_stats,
	view_rdma_stats,
	view_tp_indirect,
	view_sge_indirect,
	view_cpl_stats,
	view_ddp_stats,
	view_wc_stats,
	view_ulprx_la,
	view_lb_stats,
	view_tp_la,
	view_meminfo,
	view_cim_pif_la,
	view_clk_info,
	view_cim_q,
	view_cim_q,
	view_macstats,
	view_pcie_indirect,
	view_pm_indirect,
	view_full,
	view_tx_rate,
	view_tid,
	view_pcie_config,
	view_dump_context,
	view_mps_tcam,
	view_vpd_data,
	view_le_tcam,
	view_cctrl,
	view_ma_indirect,
	view_ulptx_la,
	view_ext_entity,
	view_up_cim_indirect,
	view_pbt_tables,
	view_mbox_log,
	view_hma_indirect,
	view_hma_data,
	view_upload,
	view_qdesc,
};

struct reg_info {
	const char *name;
	uint32_t addr;
	uint32_t len;
};

struct mod_regs {
	const char *name;
	const struct reg_info *ri;
	unsigned int offset;
};

static const char *yesno(int);
void translate_fw_devlog(void *, u32, u32 *, u32 *);
#define BIT(n)	(1U << n)

void cudbg_view_release_buff(char *pbuf, struct cudbg_buffer *dc_buff);
void cudbg_print_flash_header(void *pinbuf);
#endif
