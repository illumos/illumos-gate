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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_CFG_H
#define	_SYS_IB_ADAPTERS_TAVOR_CFG_H

/*
 * tavor_cfg.h
 *    Contains some prototypes and the structure needed to provided the
 *    Tavor Configuration Profile variables.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following define specifies the number of ports provided by the Tavor
 * hardware.  While the Tavor hardware does have two ports, it is not always
 * necessary to use both (and in some cases it may be desirable not to).
 * This define is used to set the "tavor_num_ports" configuration variable.
 * The only other legal value for "tavor_num_ports" (besides two) is one.  If
 * that variable is set to one, then only port number 1 will be active and
 * usable.  This define, however, should not be changed.
 */
#define	TAVOR_NUM_PORTS			2

/*
 * DDR Sizes.  We support 256MB / 128MB DIMMs. These defines give us the
 * size to check against in the cfg_profile_init.
 */
#define	TAVOR_DDR_SIZE_256	(1 << 28)
#define	TAVOR_DDR_SIZE_128	(1 << 27)

/*
 * Minimal configuration value.
 */
#define	TAVOR_DDR_SIZE_MIN	(1 << 25)

/*
 * The tavor_cfg_profile_t structure is used internally by the Tavor driver
 * to hold all of the configuration information for the driver.  It contains
 * information such as the maximum number (and size) of Tavor's queue pairs.
 * completion queues, translation tables, etc.  It also contains configuration
 * information such as whether the device is using agents in the Tavor
 * firmware (i.e. SMA, PMA, BMA) or whether it must register with the IBMF
 * for management requests.  Each of the fields is described below.
 */
typedef struct tavor_cfg_profile_s {
	/* Number of supported QPs and their maximum size */
	uint32_t	cp_log_num_qp;
	uint32_t	cp_log_max_qp_sz;

	/* Number of supported SGL per WQE */
	uint32_t	cp_wqe_max_sgl;
	uint32_t	cp_wqe_real_max_sgl;

	/* Number of supported CQs and their maximum size */
	uint32_t	cp_log_num_cq;
	uint32_t	cp_log_max_cq_sz;

	/* Select to enable SRQ or not; overrides the firmware setting */
	uint32_t	cp_srq_enable;
	uint32_t	cp_srq_wq_inddr;

	/* Number of supported SRQs and their maximum size */
	uint32_t	cp_log_num_srq;
	uint32_t	cp_log_max_srq_sz;
	uint32_t	cp_srq_max_sgl;

	/* Select to enable FMR or not */
	uint32_t	cp_fmr_enable;

	/* The max remaps of a particular fmr */
	uint32_t	cp_fmr_max_remaps;

	/* Default size for all EQs */
	uint32_t	cp_log_default_eq_sz;

	/* Number of supported RDB (for incoming RDMA Read/Atomic) */
	uint32_t	cp_log_num_rdb;

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
	 * maximum size.  Also the number of MTT per "MTT segment" (see
	 * tavor_mr.h for more details)
	 */
	uint32_t	cp_log_num_mpt;
	uint32_t	cp_log_max_mrw_sz;
	uint32_t	cp_log_num_mttseg;

	/*
	 * Number of supported Tavor mailboxes ("In" and "Out") and their
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

	/*
	 * Whether DMA mappings should be made with DDI_DMA_STREAMING or
	 * with DDI_DMA_CONSISTENT mode
	 */
	uint32_t	cp_streaming_consistent;

	/*
	 * Whether to override the necessity for ddi_dma_sync() calls on system
	 * memory which has been mapped DDI_DMA_CONSISTENT
	 */
	uint32_t	cp_consistent_syncoverride;

	/* Whether DMA mappings should bypass the PCI IOMMU or not */
	uint32_t	cp_iommu_bypass;
	uint32_t	cp_disable_streaming_on_bypass;

	/*
	 * Whether QP work queues should be allocated from system memory or
	 * from Tavor DDR memory
	 */
	uint32_t	cp_qp_wq_inddr;

	/* Delay after software reset */
	uint32_t	cp_sw_reset_delay;

	/* Time to wait in-between attempts to poll the 'go' bit */
	uint32_t	cp_cmd_poll_delay;

	/* Max time to continue to poll the 'go bit */
	uint32_t	cp_cmd_poll_max;

	/* Default AckReq frequency */
	uint32_t	cp_ackreq_freq;

	/* Default maximum number of outstanding split transations */
	uint32_t	cp_max_out_splt_trans;

	/* Default maximum number of bytes per read burst */
	uint32_t	cp_max_mem_rd_byte_cnt;

	/* Specify whether to use MSI (if available) */
	uint32_t	cp_use_msi_if_avail;

	/*
	 * Used to override SystemImageGUID, NodeGUID and PortGUID(s) as
	 * specified by the Tavor device node properties
	 */
	uint64_t	cp_sysimgguid;
	uint64_t	cp_nodeguid;
	uint64_t	cp_portguid[TAVOR_NUM_PORTS];

} tavor_cfg_profile_t;

int tavor_cfg_profile_init_phase1(tavor_state_t *state);
int tavor_cfg_profile_init_phase2(tavor_state_t *state);
void tavor_cfg_profile_fini(tavor_state_t *state);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_CFG_H */
