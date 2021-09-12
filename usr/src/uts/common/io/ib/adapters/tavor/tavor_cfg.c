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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tavor_cfg.c
 *    Tavor Configuration Profile Routines
 *
 *    Implements the routines necessary for initializing and (later) tearing
 *    down the list of Tavor configuration information.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/tavor/tavor.h>

/* Set to enable alternative configurations: 0 = automatic config, 1 = manual */
uint32_t tavor_alt_config_enable	= 0;

/* Number of supported QPs and their maximum size */
uint32_t tavor_log_num_qp		= TAVOR_NUM_QP_SHIFT_128;
uint32_t tavor_log_max_qp_sz		= TAVOR_QP_SZ_SHIFT;

/* Number of supported SGL per WQE */
uint32_t tavor_wqe_max_sgl		= TAVOR_NUM_WQE_SGL;

/* Number of supported CQs and their maximum size */
uint32_t tavor_log_num_cq		= TAVOR_NUM_CQ_SHIFT_128;
uint32_t tavor_log_max_cq_sz		= TAVOR_CQ_SZ_SHIFT;

/* Select to enable SRQ or not; NOTE: 0 for disabled, 1 for enabled */
uint32_t tavor_srq_enable		= 1;

/* Number of supported SRQs and their maximum size */
uint32_t tavor_log_num_srq		= TAVOR_NUM_SRQ_SHIFT_128;
uint32_t tavor_log_max_srq_sz		= TAVOR_SRQ_SZ_SHIFT;
uint32_t tavor_srq_max_sgl		= TAVOR_SRQ_MAX_SGL;

/* Default size for all EQs */
uint32_t tavor_log_default_eq_sz	= TAVOR_DEFAULT_EQ_SZ_SHIFT;

/* Number of supported RDB (for incoming RDMA Read/Atomic) */
uint32_t tavor_log_num_rdb		= TAVOR_NUM_RDB_SHIFT_128;

/*
 * Number of support multicast groups, number of QP per multicast group, and
 * the number of entries (from the total number) in the multicast group "hash
 * table"
 */
uint32_t tavor_log_num_mcg		= TAVOR_NUM_MCG_SHIFT;
uint32_t tavor_num_qp_per_mcg		= TAVOR_NUM_QP_PER_MCG;
uint32_t tavor_log_num_mcg_hash		= TAVOR_NUM_MCG_HASH_SHIFT;

/*
 * Number of supported MPTs (memory regions and windows) and their maximum
 * size.  Also the number of MTT per "MTT segment" (see tavor_mr.h for more
 * details)
 */
uint32_t tavor_log_num_mpt		= TAVOR_NUM_MPT_SHIFT_128;
uint32_t tavor_log_max_mrw_sz		= TAVOR_MAX_MEM_MPT_SHIFT_128;
uint32_t tavor_log_num_mttseg		= TAVOR_NUM_MTTSEG_SHIFT;

/*
 * Number of supported Tavor mailboxes ("In" and "Out") and their maximum
 * sizes, respectively
 */
uint32_t tavor_log_num_inmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
uint32_t tavor_log_num_outmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
uint32_t tavor_log_num_intr_inmbox	= TAVOR_NUM_INTR_MAILBOXES_SHIFT;
uint32_t tavor_log_num_intr_outmbox	= TAVOR_NUM_INTR_MAILBOXES_SHIFT;
uint32_t tavor_log_inmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
uint32_t tavor_log_outmbox_size		= TAVOR_MBOX_SIZE_SHIFT;

/* Number of supported UAR pages */
uint32_t tavor_log_num_uar		= TAVOR_NUM_UAR_SHIFT;

/* Number of supported Protection Domains (PD) */
uint32_t tavor_log_num_pd		= TAVOR_NUM_PD_SHIFT;

/* Number of supported Address Handles (AH) */
uint32_t tavor_log_num_ah		= TAVOR_NUM_AH_SHIFT;

/*
 * Number of total supported PKeys per PKey table (i.e.
 * per port).  Also the number of SGID per GID table.
 */
uint32_t tavor_log_max_pkeytbl		= TAVOR_NUM_PKEYTBL_SHIFT;
uint32_t tavor_log_max_gidtbl		= TAVOR_NUM_GIDTBL_SHIFT;

/* Maximum "responder resources" (in) and "initiator depth" (out) per QP */
uint32_t tavor_hca_max_rdma_in_qp	= TAVOR_HCA_MAX_RDMA_IN_QP;
uint32_t tavor_hca_max_rdma_out_qp	= TAVOR_HCA_MAX_RDMA_OUT_QP;

/* Maximum supported MTU and portwidth */
uint32_t tavor_max_mtu			= TAVOR_MAX_MTU;
uint32_t tavor_max_port_width		= TAVOR_MAX_PORT_WIDTH;

/* Number of supported Virtual Lanes (VL) */
uint32_t tavor_max_vlcap		= TAVOR_MAX_VLCAP;

/* Number of supported ports (1 or 2) */
uint32_t tavor_num_ports		= TAVOR_NUM_PORTS;

/*
 * Whether or not to use the built-in (i.e. in firmware) agents for QP0 and
 * QP1, respectively.
 */
uint32_t tavor_qp0_agents_in_fw		= 1;
uint32_t tavor_qp1_agents_in_fw		= 0;

/*
 * Whether DMA mappings should be made with DDI_DMA_STREAMING or with
 * DDI_DMA_CONSISTENT mode.  Note: 0 for "streaming", 1 for "consistent"
 */
uint32_t tavor_streaming_consistent	= 1;

/*
 * For DMA mappings made with DDI_DMA_CONSISTENT, this flag determines
 * whether to override the necessity for calls to ddi_dma_sync().
 */
uint32_t tavor_consistent_syncoverride  = 0;

/*
 * Whether DMA mappings should bypass the PCI IOMMU or not.
 * tavor_iommu_bypass is a global setting for all memory addresses.  However,
 * if set to BYPASS, memory attempted to be registered for streaming (ie:
 * NON-COHERENT) will necessarily turn off BYPASS for that registration.  To
 * instead disable streaming in this situation the
 * 'tavor_disable_streaming_on_bypass' can be set to 1.  This setting will
 * change the memory mapping to be implicitly consistent (ie: COHERENT), and
 * will still perform the iommu BYPASS operation.
 */
uint32_t tavor_iommu_bypass		= 1;
uint32_t tavor_disable_streaming_on_bypass = 0;

/*
 * Whether QP work queues should be allocated from system memory or
 * from Tavor DDR memory.  Note: 0 for system memory, 1 for DDR memory
 */
uint32_t tavor_qp_wq_inddr		= 0;

/*
 * Whether SRQ work queues should be allocated from system memory or
 * from Tavor DDR memory.  Note: 0 for system memory, 1 for DDR memory
 */
uint32_t tavor_srq_wq_inddr		= 0;

/*
 * Whether Tavor should use MSI (Message Signaled Interrupts), if available.
 * Note: 0 indicates 'legacy interrupt', 1 indicates MSI (if available)
 */
uint32_t tavor_use_msi_if_avail		= 1;

/*
 * This is a patchable variable that determines the time we will wait after
 * initiating SW reset before we do our first read from Tavor config space.
 * If this value is set too small (less than the default 100ms), it is
 * possible for Tavor hardware to be unready to respond to the config cycle
 * reads.  This could cause master abort on the PCI bridge.  Note: If
 * "tavor_sw_reset_delay" is set to zero, then no software reset of the Tavor
 * device will be attempted.
 */
uint32_t tavor_sw_reset_delay		= TAVOR_SW_RESET_DELAY;

/*
 * These are patchable variables for tavor command polling. The poll_delay is
 * the number of usec to wait in-between calls to poll the 'go' bit.  The
 * poll_max is the total number of usec to loop in waiting for the 'go' bit to
 * clear.
 */
uint32_t tavor_cmd_poll_delay		= TAVOR_CMD_POLL_DELAY;
uint32_t tavor_cmd_poll_max		= TAVOR_CMD_POLL_MAX;

/*
 * This is a patchable variable that determines the frequency with which
 * the AckReq bit will be set in outgoing RC packets.  The AckReq bit will be
 * set in at least every 2^tavor_qp_ackreq_freq packets (but at least once
 * per message, i.e. in the last packet).  Tuning this value can increase
 * IB fabric utilization by cutting down on the number of unnecessary ACKs.
 */
uint32_t tavor_qp_ackreq_freq		= TAVOR_QP_ACKREQ_FREQ;

/*
 * This is a patchable variable that determines the default value for the
 * maximum number of outstanding split transactions.  The number of
 * outstanding split transations (i.e. PCI reads) has an affect on device
 * throughput.  The value here should not be modified as it defines the
 * default (least common denominator - one (1) PCI read) behavior that is
 * guaranteed to work, regardless of how the Tavor firmware has been
 * initialized.  The format for this variable is the same as the corresponding
 * field in the "PCI-X Command Register".
 */
#ifdef	__sparc
/*
 * Default SPARC platforms to be 1 outstanding PCI read.
 */
int tavor_max_out_splt_trans	= 0;
#else
/*
 * Default non-SPARC platforms to be the default as set in tavor firmware
 * number of outstanding PCI reads.
 */
int tavor_max_out_splt_trans	= -1;
#endif

/*
 * This is a patchable variable that determines the default value for the
 * maximum size of PCI read burst.  This maximum size has an affect on
 * device throughput.  The value here should not be modified as it defines
 * the default (least common denominator - 512B read) behavior that is
 * guaranteed to work, regardless of how the Tavor device has been
 * initialized.  The format for this variable is the same as the corresponding
 * field in the "PCI-X Command Register".
 */
#ifdef	__sparc
/*
 * Default SPARC platforms to be 512B read.
 */
int tavor_max_mem_rd_byte_cnt	= 0;
static void tavor_check_iommu_bypass(tavor_state_t *state,
    tavor_cfg_profile_t *cp);
#else
/*
 * Default non-SPARC platforms to be the default as set in tavor firmware.
 *
 */
int tavor_max_mem_rd_byte_cnt	= -1;
#endif

static void tavor_cfg_wqe_sizes(tavor_cfg_profile_t *cp);
static void tavor_cfg_prop_lookup(tavor_state_t *state,
    tavor_cfg_profile_t *cp);

/*
 * tavor_cfg_profile_init_phase1()
 *    Context: Only called from attach() path context
 */
int
tavor_cfg_profile_init_phase1(tavor_state_t *state)
{
	tavor_cfg_profile_t	*cp;

	/*
	 * Allocate space for the configuration profile structure
	 */
	cp = (tavor_cfg_profile_t *)kmem_zalloc(sizeof (tavor_cfg_profile_t),
	    KM_SLEEP);

	cp->cp_qp0_agents_in_fw		= tavor_qp0_agents_in_fw;
	cp->cp_qp1_agents_in_fw		= tavor_qp1_agents_in_fw;
	cp->cp_sw_reset_delay		= tavor_sw_reset_delay;
	cp->cp_cmd_poll_delay		= tavor_cmd_poll_delay;
	cp->cp_cmd_poll_max		= tavor_cmd_poll_max;
	cp->cp_ackreq_freq		= tavor_qp_ackreq_freq;
	cp->cp_max_out_splt_trans	= tavor_max_out_splt_trans;
	cp->cp_max_mem_rd_byte_cnt	= tavor_max_mem_rd_byte_cnt;
	cp->cp_srq_enable		= tavor_srq_enable;
	cp->cp_fmr_enable		= 0;
	cp->cp_fmr_max_remaps		= 0;

	/*
	 * Although most of the configuration is enabled in "phase2" of the
	 * cfg_profile_init, we have to setup the OUT mailboxes here, since
	 * they are used immediately after this "phase1" completes.  Check for
	 * alt_config_enable, and set the values appropriately.  Otherwise, the
	 * config profile is setup using the values based on the dimm size.
	 * While it is expected that the mailbox size and number will remain
	 * the same independent of dimm size, we separate it out here anyway
	 * for completeness.
	 *
	 * We have to setup SRQ settings here because MOD_STAT_CFG must be
	 * called before our call to QUERY_DEVLIM.  If SRQ is enabled, then we
	 * must enable it in the firmware so that the phase2 settings will have
	 * the right device limits.
	 */
	if (tavor_alt_config_enable) {
		cp->cp_log_num_outmbox		= tavor_log_num_outmbox;
		cp->cp_log_num_intr_outmbox	= tavor_log_num_intr_outmbox;
		cp->cp_log_outmbox_size		= tavor_log_outmbox_size;
		cp->cp_log_num_inmbox		= tavor_log_num_inmbox;
		cp->cp_log_num_intr_inmbox	= tavor_log_num_intr_inmbox;
		cp->cp_log_inmbox_size		= tavor_log_inmbox_size;
		cp->cp_log_num_srq		= tavor_log_num_srq;
		cp->cp_log_max_srq_sz		= tavor_log_max_srq_sz;

	} else if (state->ts_cfg_profile_setting >= TAVOR_DDR_SIZE_256) {
		cp->cp_log_num_outmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
		cp->cp_log_num_intr_outmbox	=
		    TAVOR_NUM_INTR_MAILBOXES_SHIFT;
		cp->cp_log_outmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
		cp->cp_log_num_inmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
		cp->cp_log_num_intr_inmbox	=
		    TAVOR_NUM_INTR_MAILBOXES_SHIFT;
		cp->cp_log_inmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
		cp->cp_log_num_srq		= TAVOR_NUM_SRQ_SHIFT_256;
		cp->cp_log_max_srq_sz		= TAVOR_SRQ_SZ_SHIFT;

	} else if (state->ts_cfg_profile_setting == TAVOR_DDR_SIZE_128) {
		cp->cp_log_num_outmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
		cp->cp_log_num_intr_outmbox	=
		    TAVOR_NUM_INTR_MAILBOXES_SHIFT;
		cp->cp_log_outmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
		cp->cp_log_num_inmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
		cp->cp_log_num_intr_inmbox	=
		    TAVOR_NUM_INTR_MAILBOXES_SHIFT;
		cp->cp_log_inmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
		cp->cp_log_num_srq		= TAVOR_NUM_SRQ_SHIFT_128;
		cp->cp_log_max_srq_sz		= TAVOR_SRQ_SZ_SHIFT;

	} else if (state->ts_cfg_profile_setting == TAVOR_DDR_SIZE_MIN) {
		cp->cp_log_num_outmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
		cp->cp_log_num_intr_outmbox	=
		    TAVOR_NUM_INTR_MAILBOXES_SHIFT;
		cp->cp_log_outmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
		cp->cp_log_num_inmbox		= TAVOR_NUM_MAILBOXES_SHIFT;
		cp->cp_log_num_intr_inmbox	=
		    TAVOR_NUM_INTR_MAILBOXES_SHIFT;
		cp->cp_log_inmbox_size		= TAVOR_MBOX_SIZE_SHIFT;
		cp->cp_log_num_srq		= TAVOR_NUM_SRQ_SHIFT_MIN;
		cp->cp_log_max_srq_sz		= TAVOR_SRQ_SZ_SHIFT_MIN;

	} else {
		return (DDI_FAILURE);
	}

	/*
	 * Set default DMA mapping mode.  Ensure consistency of flags
	 * with both architecture type and other configuration flags.
	 */
	if (tavor_streaming_consistent == 0) {
#ifdef	__sparc
		cp->cp_streaming_consistent = DDI_DMA_STREAMING;

		/* Can't do both "streaming" and IOMMU bypass */
		if (tavor_iommu_bypass != 0) {
			kmem_free(cp, sizeof (tavor_cfg_profile_t));
			return (DDI_FAILURE);
		}
#else
		cp->cp_streaming_consistent = DDI_DMA_CONSISTENT;
#endif
	} else {
		cp->cp_streaming_consistent = DDI_DMA_CONSISTENT;
	}

	/* Determine whether to override ddi_dma_sync() */
	cp->cp_consistent_syncoverride = tavor_consistent_syncoverride;

	/* Attach the configuration profile to Tavor softstate */
	state->ts_cfg_profile = cp;

	return (DDI_SUCCESS);
}

/*
 * tavor_cfg_profile_init_phase2()
 *    Context: Only called from attach() path context
 */
int
tavor_cfg_profile_init_phase2(tavor_state_t *state)
{
	tavor_cfg_profile_t	*cp;

	/* Read the configuration profile from Tavor softstate */
	cp = state->ts_cfg_profile;

	/*
	 * Verify the config profile setting.  The 'setting' should already be
	 * set, during a call to ddi_dev_regsize() to get the size of DDR
	 * memory, or during a fallback to a smaller supported size.  If it is
	 * not set, we should not have reached this 'phase2'.  So we assert
	 * here.
	 */
	ASSERT(state->ts_cfg_profile_setting != 0);

	/*
	 * The automatic configuration override is the
	 * 'tavor_alt_config_enable' variable.  If this is set, we no longer
	 * use the DIMM size to enable the correct profile.  Instead, all of
	 * the tavor config options at the top of this file are used directly.
	 *
	 * This allows customization for a user who knows what they are doing
	 * to set tavor configuration values manually.
	 *
	 * If this variable is 0, we do automatic config for both 128MB and
	 * 256MB DIMM sizes.
	 */
	if (tavor_alt_config_enable) {
		/*
		 * Initialize the configuration profile
		 */
		cp->cp_log_num_qp		= tavor_log_num_qp;
		cp->cp_log_max_qp_sz		= tavor_log_max_qp_sz;

		/* Determine WQE sizes from requested max SGLs */
		tavor_cfg_wqe_sizes(cp);

		cp->cp_log_num_cq		= tavor_log_num_cq;
		cp->cp_log_max_cq_sz		= tavor_log_max_cq_sz;
		cp->cp_log_default_eq_sz	= tavor_log_default_eq_sz;
		cp->cp_log_num_rdb		= tavor_log_num_rdb;
		cp->cp_log_num_mcg		= tavor_log_num_mcg;
		cp->cp_num_qp_per_mcg		= tavor_num_qp_per_mcg;
		cp->cp_log_num_mcg_hash		= tavor_log_num_mcg_hash;
		cp->cp_log_num_mpt		= tavor_log_num_mpt;
		cp->cp_log_max_mrw_sz		= tavor_log_max_mrw_sz;
		cp->cp_log_num_mttseg		= tavor_log_num_mttseg;
		cp->cp_log_num_uar		= tavor_log_num_uar;
		cp->cp_log_num_pd		= tavor_log_num_pd;
		cp->cp_log_num_ah		= tavor_log_num_ah;
		cp->cp_log_max_pkeytbl		= tavor_log_max_pkeytbl;
		cp->cp_log_max_gidtbl		= tavor_log_max_gidtbl;
		cp->cp_hca_max_rdma_in_qp	= tavor_hca_max_rdma_in_qp;
		cp->cp_hca_max_rdma_out_qp	= tavor_hca_max_rdma_out_qp;
		cp->cp_max_mtu			= tavor_max_mtu;
		cp->cp_max_port_width		= tavor_max_port_width;
		cp->cp_max_vlcap		= tavor_max_vlcap;
		cp->cp_num_ports		= tavor_num_ports;
		cp->cp_qp0_agents_in_fw		= tavor_qp0_agents_in_fw;
		cp->cp_qp1_agents_in_fw		= tavor_qp1_agents_in_fw;
		cp->cp_sw_reset_delay		= tavor_sw_reset_delay;
		cp->cp_ackreq_freq		= tavor_qp_ackreq_freq;
		cp->cp_max_out_splt_trans	= tavor_max_out_splt_trans;
		cp->cp_max_mem_rd_byte_cnt	= tavor_max_mem_rd_byte_cnt;

	} else if (state->ts_cfg_profile_setting >= TAVOR_DDR_SIZE_256) {
		/*
		 * Initialize the configuration profile
		 */
		cp->cp_log_num_qp		= TAVOR_NUM_QP_SHIFT_256;
		cp->cp_log_max_qp_sz		= TAVOR_QP_SZ_SHIFT;

		/* Determine WQE sizes from requested max SGLs */
		tavor_cfg_wqe_sizes(cp);

		cp->cp_log_num_cq		= TAVOR_NUM_CQ_SHIFT_256;
		cp->cp_log_max_cq_sz		= TAVOR_CQ_SZ_SHIFT;
		cp->cp_log_default_eq_sz	= TAVOR_DEFAULT_EQ_SZ_SHIFT;
		cp->cp_log_num_rdb		= TAVOR_NUM_RDB_SHIFT_256;
		cp->cp_log_num_mcg		= TAVOR_NUM_MCG_SHIFT;
		cp->cp_num_qp_per_mcg		= TAVOR_NUM_QP_PER_MCG;
		cp->cp_log_num_mcg_hash		= TAVOR_NUM_MCG_HASH_SHIFT;
		cp->cp_log_num_mpt		= TAVOR_NUM_MPT_SHIFT_256;
		cp->cp_log_max_mrw_sz		= TAVOR_MAX_MEM_MPT_SHIFT_256;
		cp->cp_log_num_mttseg		= TAVOR_NUM_MTTSEG_SHIFT;
		cp->cp_log_num_uar		= TAVOR_NUM_UAR_SHIFT;
		cp->cp_log_num_pd		= TAVOR_NUM_PD_SHIFT;
		cp->cp_log_num_ah		= TAVOR_NUM_AH_SHIFT;
		cp->cp_log_max_pkeytbl		= TAVOR_NUM_PKEYTBL_SHIFT;
		cp->cp_log_max_gidtbl		= TAVOR_NUM_GIDTBL_SHIFT;
		cp->cp_hca_max_rdma_in_qp	= TAVOR_HCA_MAX_RDMA_IN_QP;
		cp->cp_hca_max_rdma_out_qp	= TAVOR_HCA_MAX_RDMA_OUT_QP;
		cp->cp_max_mtu			= TAVOR_MAX_MTU;
		cp->cp_max_port_width		= TAVOR_MAX_PORT_WIDTH;
		cp->cp_max_vlcap		= TAVOR_MAX_VLCAP;
		cp->cp_num_ports		= TAVOR_NUM_PORTS;
		cp->cp_qp0_agents_in_fw		= tavor_qp0_agents_in_fw;
		cp->cp_qp1_agents_in_fw		= tavor_qp1_agents_in_fw;
		cp->cp_sw_reset_delay		= tavor_sw_reset_delay;
		cp->cp_ackreq_freq		= tavor_qp_ackreq_freq;
		cp->cp_max_out_splt_trans	= tavor_max_out_splt_trans;
		cp->cp_max_mem_rd_byte_cnt	= tavor_max_mem_rd_byte_cnt;

	} else if (state->ts_cfg_profile_setting == TAVOR_DDR_SIZE_128) {
		/*
		 * Initialize the configuration profile
		 */
		cp->cp_log_num_qp		= TAVOR_NUM_QP_SHIFT_128;
		cp->cp_log_max_qp_sz		= TAVOR_QP_SZ_SHIFT;

		/* Determine WQE sizes from requested max SGLs */
		tavor_cfg_wqe_sizes(cp);

		cp->cp_log_num_cq		= TAVOR_NUM_CQ_SHIFT_128;
		cp->cp_log_max_cq_sz		= TAVOR_CQ_SZ_SHIFT;
		cp->cp_log_default_eq_sz	= TAVOR_DEFAULT_EQ_SZ_SHIFT;
		cp->cp_log_num_rdb		= TAVOR_NUM_RDB_SHIFT_128;
		cp->cp_log_num_mcg		= TAVOR_NUM_MCG_SHIFT;
		cp->cp_num_qp_per_mcg		= TAVOR_NUM_QP_PER_MCG;
		cp->cp_log_num_mcg_hash		= TAVOR_NUM_MCG_HASH_SHIFT;
		cp->cp_log_num_mpt		= TAVOR_NUM_MPT_SHIFT_128;
		cp->cp_log_max_mrw_sz		= TAVOR_MAX_MEM_MPT_SHIFT_128;
		cp->cp_log_num_mttseg		= TAVOR_NUM_MTTSEG_SHIFT;
		cp->cp_log_num_uar		= TAVOR_NUM_UAR_SHIFT;
		cp->cp_log_num_pd		= TAVOR_NUM_PD_SHIFT;
		cp->cp_log_num_ah		= TAVOR_NUM_AH_SHIFT;
		cp->cp_log_max_pkeytbl		= TAVOR_NUM_PKEYTBL_SHIFT;
		cp->cp_log_max_gidtbl		= TAVOR_NUM_GIDTBL_SHIFT;
		cp->cp_hca_max_rdma_in_qp	= TAVOR_HCA_MAX_RDMA_IN_QP;
		cp->cp_hca_max_rdma_out_qp	= TAVOR_HCA_MAX_RDMA_OUT_QP;
		cp->cp_max_mtu			= TAVOR_MAX_MTU;
		cp->cp_max_port_width		= TAVOR_MAX_PORT_WIDTH;
		cp->cp_max_vlcap		= TAVOR_MAX_VLCAP;
		cp->cp_num_ports		= TAVOR_NUM_PORTS;
		cp->cp_qp0_agents_in_fw		= tavor_qp0_agents_in_fw;
		cp->cp_qp1_agents_in_fw		= tavor_qp1_agents_in_fw;
		cp->cp_sw_reset_delay		= tavor_sw_reset_delay;
		cp->cp_ackreq_freq		= tavor_qp_ackreq_freq;
		cp->cp_max_out_splt_trans	= tavor_max_out_splt_trans;
		cp->cp_max_mem_rd_byte_cnt	= tavor_max_mem_rd_byte_cnt;

	} else if (state->ts_cfg_profile_setting == TAVOR_DDR_SIZE_MIN) {
		/*
		 * Initialize the configuration profile for minimal footprint.
		 */

		cp->cp_log_num_qp		= TAVOR_NUM_QP_SHIFT_MIN;
		cp->cp_log_max_qp_sz		= TAVOR_QP_SZ_SHIFT_MIN;

		/* Determine WQE sizes from requested max SGLs */
		tavor_cfg_wqe_sizes(cp);

		cp->cp_log_num_cq		= TAVOR_NUM_CQ_SHIFT_MIN;
		cp->cp_log_max_cq_sz		= TAVOR_CQ_SZ_SHIFT_MIN;
		cp->cp_log_default_eq_sz	= TAVOR_DEFAULT_EQ_SZ_SHIFT;
		cp->cp_log_num_rdb		= TAVOR_NUM_RDB_SHIFT_MIN;
		cp->cp_log_num_mcg		= TAVOR_NUM_MCG_SHIFT_MIN;
		cp->cp_num_qp_per_mcg		= TAVOR_NUM_QP_PER_MCG_MIN;
		cp->cp_log_num_mcg_hash		= TAVOR_NUM_MCG_HASH_SHIFT_MIN;
		cp->cp_log_num_mpt		= TAVOR_NUM_MPT_SHIFT_MIN;
		cp->cp_log_max_mrw_sz		= TAVOR_MAX_MEM_MPT_SHIFT_MIN;
		cp->cp_log_num_mttseg		= TAVOR_NUM_MTTSEG_SHIFT_MIN;
		cp->cp_log_num_uar		= TAVOR_NUM_UAR_SHIFT_MIN;
		cp->cp_log_num_pd		= TAVOR_NUM_PD_SHIFT;
		cp->cp_log_num_ah		= TAVOR_NUM_AH_SHIFT_MIN;
		cp->cp_log_max_pkeytbl		= TAVOR_NUM_PKEYTBL_SHIFT;
		cp->cp_log_max_gidtbl		= TAVOR_NUM_GIDTBL_SHIFT;
		cp->cp_hca_max_rdma_in_qp	= TAVOR_HCA_MAX_RDMA_IN_QP;
		cp->cp_hca_max_rdma_out_qp	= TAVOR_HCA_MAX_RDMA_OUT_QP;
		cp->cp_max_mtu			= TAVOR_MAX_MTU;
		cp->cp_max_port_width		= TAVOR_MAX_PORT_WIDTH;
		cp->cp_max_vlcap		= TAVOR_MAX_VLCAP;
		cp->cp_num_ports		= TAVOR_NUM_PORTS;
		cp->cp_qp0_agents_in_fw		= tavor_qp0_agents_in_fw;
		cp->cp_qp1_agents_in_fw		= tavor_qp1_agents_in_fw;
		cp->cp_sw_reset_delay		= tavor_sw_reset_delay;
		cp->cp_ackreq_freq		= tavor_qp_ackreq_freq;
		cp->cp_max_out_splt_trans	= tavor_max_out_splt_trans;
		cp->cp_max_mem_rd_byte_cnt	= tavor_max_mem_rd_byte_cnt;

	} else {
		return (DDI_FAILURE);
	}

	/*
	 * Set IOMMU bypass or not.  Ensure consistency of flags with
	 * architecture type.
	 */
#ifdef __sparc
	if (tavor_iommu_bypass == 1) {
		tavor_check_iommu_bypass(state, cp);
	} else {
		cp->cp_iommu_bypass = TAVOR_BINDMEM_NORMAL;
		cp->cp_disable_streaming_on_bypass = 0;
	}
#else
	cp->cp_iommu_bypass = TAVOR_BINDMEM_NORMAL;
	cp->cp_disable_streaming_on_bypass = 0;
#endif
	/* Set whether QP WQEs will be in DDR or not */
	cp->cp_qp_wq_inddr = (tavor_qp_wq_inddr == 0) ?
	    TAVOR_QUEUE_LOCATION_NORMAL : TAVOR_QUEUE_LOCATION_INDDR;

	/* Set whether SRQ WQEs will be in DDR or not */
	cp->cp_srq_wq_inddr = (tavor_srq_wq_inddr == 0) ?
	    TAVOR_QUEUE_LOCATION_NORMAL : TAVOR_QUEUE_LOCATION_INDDR;

	cp->cp_use_msi_if_avail = tavor_use_msi_if_avail;

	/* Determine additional configuration from optional properties */
	tavor_cfg_prop_lookup(state, cp);

	return (DDI_SUCCESS);
}


/*
 * tavor_cfg_profile_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_cfg_profile_fini(tavor_state_t *state)
{
	/*
	 * Free up the space for configuration profile
	 */
	kmem_free(state->ts_cfg_profile, sizeof (tavor_cfg_profile_t));
}


/*
 * tavor_cfg_wqe_sizes()
 *    Context: Only called from attach() path context
 */
static void
tavor_cfg_wqe_sizes(tavor_cfg_profile_t *cp)
{
	uint_t	max_size, log2;
	uint_t	max_sgl, real_max_sgl;

	/*
	 * Get the requested maximum number SGL per WQE from the Tavor
	 * patchable variable
	 */
	max_sgl = tavor_wqe_max_sgl;

	/*
	 * Use requested maximum number of SGL to calculate the max descriptor
	 * size (while guaranteeing that the descriptor size is a power-of-2
	 * cachelines).  We have to use the calculation for QP1 MLX transport
	 * because the possibility that we might need to inline a GRH, along
	 * with all the other headers and alignment restrictions, sets the
	 * maximum for the number of SGLs that we can advertise support for.
	 */
	max_size = (TAVOR_QP_WQE_MLX_QP1_HDRS + (max_sgl << 4));
	log2 = highbit(max_size);
	if (ISP2(max_size)) {
		log2 = log2 - 1;
	}
	max_size = (1 << log2);

	/*
	 * Now clip the maximum descriptor size based on Tavor HW maximum
	 */
	max_size = min(max_size, TAVOR_QP_WQE_MAX_SIZE);

	/*
	 * Then use the calculated max descriptor size to determine the "real"
	 * maximum SGL (the number beyond which we would roll over to the next
	 * power-of-2).
	 */
	real_max_sgl = (max_size - TAVOR_QP_WQE_MLX_QP1_HDRS) >> 4;

	/* Then save away this configuration information */
	cp->cp_wqe_max_sgl	= max_sgl;
	cp->cp_wqe_real_max_sgl = real_max_sgl;

	/* SRQ SGL gets set to it's own patchable variable value */
	cp->cp_srq_max_sgl		= tavor_srq_max_sgl;
}


/*
 * tavor_cfg_prop_lookup()
 *    Context: Only called from attach() path context
 */
static void
tavor_cfg_prop_lookup(tavor_state_t *state, tavor_cfg_profile_t *cp)
{
	uint_t		num_ports, nelementsp;
	uchar_t		*datap;
	int		status;

	/*
	 * Read the property defining the number of Tavor ports to
	 * support.  If the property is undefined or invalid, then return.
	 * We return here assuming also that OBP is not supposed to be setting
	 * up other properties in this case (eg: HCA plugin cards).  But if
	 * this property is valid, then we print out a message for the other
	 * properties to show an OBP error.
	 */
	num_ports = ddi_prop_get_int(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "#ports", 0);
	if ((num_ports > TAVOR_NUM_PORTS) || (num_ports == 0)) {
		return;
	}
	cp->cp_num_ports   = num_ports;

	/*
	 * The system image guid is not currently supported in the 1275
	 * binding.  So we leave this commented out for now.
	 */
#ifdef SUPPORTED_IN_1275_BINDING
	/*
	 * Read the property defining the value to use later to override the
	 * default SystemImageGUID (in firmware).  If the property is
	 * undefined, then return.
	 */
	status = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "system-image-guid", &datap, &nelementsp);
	if (status == DDI_PROP_SUCCESS) {
		cp->cp_sysimgguid = ((uint64_t *)datap)[0];
		ddi_prop_free(datap);
	} else {
		cmn_err(CE_NOTE,
		    "Unable to read OBP system-image-guid property");
	}
#endif

	/*
	 * Read the property defining the value to use later to override
	 * the default SystemImageGUID (in firmware).  If the property is
	 * undefined, then return.
	 */
	status = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "node-guid", &datap, &nelementsp);
	if (status == DDI_PROP_SUCCESS) {
		cp->cp_nodeguid = ((uint64_t *)datap)[0];
		ddi_prop_free(datap);
	} else {
		cmn_err(CE_NOTE, "Unable to read OBP node-guid property");
	}

	/*
	 * Using the value for the number of ports (above) read the properties
	 * used to later to override the default PortGUIDs for each Tavor port.
	 * If either of these properties are undefined, then return.
	 */
	if (num_ports == TAVOR_NUM_PORTS) {
		status = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY,
		    state->ts_dip, DDI_PROP_DONTPASS, "port-2-guid", &datap,
		    &nelementsp);
		if (status == DDI_PROP_SUCCESS) {
			cp->cp_portguid[1] = ((uint64_t *)datap)[0];
			ddi_prop_free(datap);
		} else {
			cmn_err(CE_NOTE,
			    "Unable to read OBP port-2-guid property");
		}
	}
	status = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "port-1-guid", &datap, &nelementsp);
	if (status == DDI_PROP_SUCCESS) {
		cp->cp_portguid[0] = ((uint64_t *)datap)[0];
		ddi_prop_free(datap);
	} else {
		cmn_err(CE_NOTE, "Unable to read OBP port-1-guid property");
	}
}

#ifdef __sparc
/*
 * tavor_check_iommu_bypass()
 *    Context: Only called from attach() path context
 */
static void
tavor_check_iommu_bypass(tavor_state_t *state, tavor_cfg_profile_t *cp)
{
	ddi_dma_handle_t	dmahdl;
	ddi_dma_attr_t		dma_attr;
	int			status;

	tavor_dma_attr_init(&dma_attr);

	/* Try mapping for IOMMU bypass (Force Physical) */
	dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;

	/*
	 * Call ddi_dma_alloc_handle().  If this returns DDI_DMA_BADATTR then
	 * it is not possible to use IOMMU bypass with our PCI bridge parent.
	 * For example, certain versions of Tomatillo do not support IOMMU
	 * bypass.  Since the function we are in can only be called if iommu
	 * bypass was requested in the config profile, we configure for bypass
	 * if the ddi_dma_alloc_handle() was successful.  Otherwise, we
	 * configure for non-bypass (ie: normal) mapping.
	 */
	status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr,
	    DDI_DMA_SLEEP, NULL, &dmahdl);
	if (status == DDI_DMA_BADATTR) {
		cp->cp_iommu_bypass = TAVOR_BINDMEM_NORMAL;
		cp->cp_disable_streaming_on_bypass = 0;
	} else {
		cp->cp_iommu_bypass = TAVOR_BINDMEM_BYPASS;
		cp->cp_disable_streaming_on_bypass =
		    tavor_disable_streaming_on_bypass;

		if (status == DDI_SUCCESS) {
			ddi_dma_free_handle(&dmahdl);
		}
	}
}
#endif
