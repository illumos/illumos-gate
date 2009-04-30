/*
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
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_CFG_H
#define	_SYS_IB_ADAPTERS_HERMON_CFG_H

/*
 * hermon_cfg.h
 *    Contains some prototypes and the structure needed to provided the
 *    Hermon Configuration Profile variables.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* For PCIe Relaxed Ordering implementation */
#define	HERMON_RO_DISABLED	0
#define	HERMON_RO_ENABLED	1

/*
 * Configuration profiles
 */
#define	HERMON_CFG_MEMFREE	0x0001

#define	HERMON_MAX_PORTS		2

#define	HERMON_LOG_CMPT_PER_TYPE	24	/* for now, allot 2**24 per */

/*
 * The hermon_cfg_profile_t structure is used internally by the Hermon driver
 * to hold all of the configuration information for the driver.  It contains
 * information such as the maximum number (and size) of Hermon's queue pairs.
 * completion queues, translation tables, etc.  It also contains configuration
 * information such as whether the device is using agents in the Hermon
 * firmware (i.e. SMA, PMA, BMA) or whether it must register with the IBMF
 * for management requests.  Each of the fields is described below.
 */
typedef struct hermon_cfg_profile_s {
	/* Number of supported QPs and their maximum size */
	uint32_t	cp_log_num_qp;
	uint32_t	cp_log_max_qp_sz;

	/* Number of supported SGL per WQE */
	uint32_t	cp_wqe_max_sgl;
	uint32_t	cp_wqe_real_max_sgl;

	/* Number of supported CQs and their maximum size */
	uint32_t	cp_log_num_cq;
	uint32_t	cp_log_max_cq_sz;

	/* Number of supported SRQs and their maximum size */
	uint32_t	cp_log_num_srq;
	uint32_t	cp_log_max_srq_sz;
	uint32_t	cp_srq_max_sgl;
	uint32_t	cp_srq_resize_enabled;

	/* The max remaps of a particular fmr */
	uint32_t	cp_fmr_max_remaps;

	/* Number of EQs, and their default size */
	uint32_t	cp_log_num_eq;
	uint32_t	cp_log_eq_sz;

	/* Number of supported RDBs and their default size */
	uint32_t	cp_log_num_rdb;
	uint32_t	cp_log_default_rdb_sz;

	/*
	 * Number of support multicast groups, number of QP per multicast
	 * group, and the number of entries (from the total number) in
	 * the multicast group "hash table"
	 */
	uint32_t	cp_log_num_mcg;
	uint32_t	cp_num_qp_per_mcg;
	uint32_t	cp_log_num_mcg_hash;

	/*
	 * Number of supported MPTs (memory regions and windows) and their
	 * maximum size.  Also the number of MTTs.
	 */
	uint32_t	cp_log_num_cmpt;	/* control MPTs */
	uint32_t	cp_log_num_dmpt;	/* data MPTs */
	uint32_t	cp_log_max_mrw_sz;
	uint32_t	cp_log_num_mtt;

	/*
	 * Number of supported Hermon mailboxes ("In" and "Out") and their
	 * maximum sizes, respectively
	 */
	uint32_t	cp_log_num_inmbox;
	uint32_t	cp_log_num_outmbox;
	uint32_t	cp_log_num_intr_inmbox;
	uint32_t	cp_log_num_intr_outmbox;
	uint32_t	cp_log_inmbox_size;
	uint32_t	cp_log_outmbox_size;

	/* Number of supported UAR pages */
	uint32_t	cp_log_num_uar;

	/* Number of ICM (4KB) pages per UAR context entry */
	uint32_t	cp_num_pgs_per_uce;

	/* Number of supported Protection Domains (PD) */
	uint32_t	cp_log_num_pd;

	/* Number of supported Address Handles (AH) */
	uint32_t	cp_log_num_ah;

	/*
	 * Number of supported PKeys per PKey table (i.e. per port).  Also the
	 * number of SGID per GID table.
	 */
	uint32_t	cp_log_max_pkeytbl;
	uint32_t	cp_log_max_gidtbl;

	/* Maximum "responder resources" and "initiator depth" per QP */
	uint32_t	cp_hca_max_rdma_in_qp;
	uint32_t	cp_hca_max_rdma_out_qp;

	/* Maximum supported MTU and port width */
	uint32_t	cp_max_mtu;
	uint32_t	cp_max_port_width;

	/* Number of supported Virtual Lanes (VL) */
	uint32_t	cp_max_vlcap;

	/* Number of supported ports (1 or 2) */
	uint32_t	cp_num_ports;

	/*
	 * Whether or not to use the built-in (i.e. in firmware) agents
	 * for QP0 and QP1, respectively
	 */
	uint32_t	cp_qp0_agents_in_fw;
	uint32_t	cp_qp1_agents_in_fw;

	/* Whether DMA mappings should bypass the PCI IOMMU or not */
	uint32_t	cp_iommu_bypass;

	/* Delay after software reset */
	uint32_t	cp_sw_reset_delay;

	/* Time to wait in-between attempts to poll the 'go' bit */
	uint32_t	cp_cmd_poll_delay;

	/* Max time to continue to poll the 'go bit */
	uint32_t	cp_cmd_poll_max;

	/* Default AckReq frequency */
	uint32_t	cp_ackreq_freq;

	/* Specify whether to use MSI (if available) */
	uint32_t	cp_use_msi_if_avail;

	/*
	 * Used to override SystemImageGUID, NodeGUID and PortGUID(s) as
	 * specified by the Hermon device node properties
	 */
	uint64_t	cp_sysimgguid;
	uint64_t	cp_nodeguid;
	uint64_t	cp_portguid[HERMON_MAX_PORTS];

} hermon_cfg_profile_t;

int hermon_cfg_profile_init_phase1(hermon_state_t *state);
int hermon_cfg_profile_init_phase2(hermon_state_t *state);
void hermon_cfg_profile_fini(hermon_state_t *state);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_CFG_H */
