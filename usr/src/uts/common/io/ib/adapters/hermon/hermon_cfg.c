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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * hermon_cfg.c
 *    Hermon Configuration Profile Routines
 *
 *    Implements the routines necessary for initializing and (later) tearing
 *    down the list of Hermon configuration information.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/hermon/hermon.h>

/*
 * Below are the elements that make up the Hermon configuration profile.
 * For advanced users who wish to alter these values, this can be done via
 * the /etc/system file. By default, values are assigned to the number of
 * supported resources, either from the HCA's reported capacities or by
 * a by-design limit in the driver.
 */

/* Number of supported QPs, CQs and SRQs */
uint32_t hermon_log_num_qp		= HERMON_NUM_QP_SHIFT;
uint32_t hermon_log_num_cq		= HERMON_NUM_CQ_SHIFT;
uint32_t hermon_log_num_srq		= HERMON_NUM_SRQ_SHIFT;

/* Number of supported SGL per WQE for SQ/RQ, and for SRQ */
/* XXX use the same for all queues if limitation in srq.h is resolved */
uint32_t hermon_wqe_max_sgl		= HERMON_NUM_SGL_PER_WQE;
uint32_t hermon_srq_max_sgl		= HERMON_SRQ_MAX_SGL;

/* Maximum "responder resources" (in) and "initiator depth" (out) per QP */
uint32_t hermon_log_num_rdb_per_qp	= HERMON_LOG_NUM_RDB_PER_QP;

/*
 * Number of multicast groups (MCGs), number of QP per MCG, and the number
 * of entries (from the total number) in the multicast group "hash table"
 */
uint32_t hermon_log_num_mcg		= HERMON_NUM_MCG_SHIFT;
uint32_t hermon_num_qp_per_mcg		= HERMON_NUM_QP_PER_MCG;
uint32_t hermon_log_num_mcg_hash	= HERMON_NUM_MCG_HASH_SHIFT;

/* Number of UD AVs */
uint32_t hermon_log_num_ah		= HERMON_NUM_AH_SHIFT;

/* Number of EQs and their default size */
uint32_t hermon_log_num_eq		= HERMON_NUM_EQ_SHIFT;
uint32_t hermon_log_eq_sz		= HERMON_DEFAULT_EQ_SZ_SHIFT;

/*
 * Number of supported MPTs, MTTs and also the maximum MPT size.
 */
uint32_t hermon_log_num_mtt		= HERMON_NUM_MTT_SHIFT;
uint32_t hermon_log_num_dmpt		= HERMON_NUM_DMPT_SHIFT;
uint32_t hermon_log_max_mrw_sz		= HERMON_MAX_MEM_MPT_SHIFT;

/*
 * Number of supported UAR (User Access Regions) for this HCA.
 * We could in the future read in uar_sz from devlim, and thus
 * derive the number of UAR. Since this is derived from PAGESIZE,
 * however, this means that x86 systems would have twice as many
 * UARs as SPARC systems. Therefore for consistency's sake, we will
 * just use 1024 pages, which is the maximum on SPARC systems.
 */
uint32_t hermon_log_num_uar		= HERMON_NUM_UAR_SHIFT;

/*
 * Number of remaps allowed for FMR before a sync is required.  This value
 * determines how many times we can fmr_deregister() before the underlying fmr
 * framework places the region to wait for an MTT_SYNC operation, cleaning up
 * the old mappings.
 */
uint32_t hermon_fmr_num_remaps		= HERMON_FMR_MAX_REMAPS;

/*
 * Number of supported Hermon mailboxes ("In" and "Out") and their maximum
 * sizes, respectively
 */
uint32_t hermon_log_num_inmbox		= HERMON_NUM_MAILBOXES_SHIFT;
uint32_t hermon_log_num_outmbox		= HERMON_NUM_MAILBOXES_SHIFT;
uint32_t hermon_log_inmbox_size		= HERMON_MBOX_SIZE_SHIFT;
uint32_t hermon_log_outmbox_size	= HERMON_MBOX_SIZE_SHIFT;
uint32_t hermon_log_num_intr_inmbox	= HERMON_NUM_INTR_MAILBOXES_SHIFT;
uint32_t hermon_log_num_intr_outmbox	= HERMON_NUM_INTR_MAILBOXES_SHIFT;

/* Number of supported Protection Domains (PD) */
uint32_t hermon_log_num_pd		= HERMON_NUM_PD_SHIFT;

/*
 * Number of total supported PKeys per PKey table (i.e.
 * per port).  Also the number of SGID per GID table.
 */
uint32_t hermon_log_max_pkeytbl		= HERMON_NUM_PKEYTBL_SHIFT;
uint32_t hermon_log_max_gidtbl		= HERMON_NUM_GIDTBL_SHIFT;

/* Maximum supported MTU and portwidth */
uint32_t hermon_max_mtu			= HERMON_MAX_MTU;
uint32_t hermon_max_port_width		= HERMON_MAX_PORT_WIDTH;

/* Number of supported Virtual Lanes (VL) */
uint32_t hermon_max_vlcap		= HERMON_MAX_VLCAP;

/*
 * Whether or not to use the built-in (i.e. in firmware) agents for QP0 and
 * QP1, respectively.
 */
uint32_t hermon_qp0_agents_in_fw	= 0;
uint32_t hermon_qp1_agents_in_fw	= 0;

/*
 * Whether DMA mappings should bypass the PCI IOMMU or not.
 * hermon_iommu_bypass is a global setting for all memory addresses.
 */
uint32_t hermon_iommu_bypass		= 1;

/*
 * Whether *DATA* buffers should be bound w/ Relaxed Ordering (RO) turned on
 * via the SW workaround (HCAs don't support RO in HW).  Defaulted on,
 * though care must be taken w/ some Userland clients that *MAY* have
 * peeked in the data to understand when data xfer was done - MPI does
 * as an efficiency
 */

uint32_t hermon_kernel_data_ro		= HERMON_RO_ENABLED;	/* default */
uint32_t hermon_user_data_ro		= HERMON_RO_ENABLED;	/* default */

/*
 * Whether Hermon should use MSI (Message Signaled Interrupts), if available.
 * Note: 0 indicates 'legacy interrupt', 1 indicates MSI (if available)
 */
uint32_t hermon_use_msi_if_avail	= 1;

/*
 * This is a patchable variable that determines the time we will wait after
 * initiating SW reset before we do our first read from Hermon config space.
 * If this value is set too small (less than the default 100ms), it is
 * possible for Hermon hardware to be unready to respond to the config cycle
 * reads.  This could cause master abort on the PCI bridge.  Note: If
 * "hermon_sw_reset_delay" is set to zero, then no software reset of the Hermon
 * device will be attempted.
 */
uint32_t hermon_sw_reset_delay		= HERMON_SW_RESET_DELAY;

/*
 * These are patchable variables for hermon command polling. The poll_delay is
 * the number of usec to wait in-between calls to poll the 'go' bit.  The
 * poll_max is the total number of usec to loop in waiting for the 'go' bit to
 * clear.
 */
uint32_t hermon_cmd_poll_delay		= HERMON_CMD_POLL_DELAY;
uint32_t hermon_cmd_poll_max		= HERMON_CMD_POLL_MAX;

/*
 * This is a patchable variable that determines the frequency with which
 * the AckReq bit will be set in outgoing RC packets.  The AckReq bit will be
 * set in at least every 2^hermon_qp_ackreq_freq packets (but at least once
 * per message, i.e. in the last packet).  Tuning this value can increase
 * IB fabric utilization by cutting down on the number of unnecessary ACKs.
 */
uint32_t hermon_qp_ackreq_freq		= HERMON_QP_ACKREQ_FREQ;

static void hermon_cfg_wqe_sizes(hermon_state_t *state,
    hermon_cfg_profile_t *cp);
#ifdef __sparc
static void hermon_check_iommu_bypass(hermon_state_t *state,
    hermon_cfg_profile_t *cp);
#endif

/*
 * hermon_cfg_profile_init_phase1()
 *    Context: Only called from attach() path context
 */
int
hermon_cfg_profile_init_phase1(hermon_state_t *state)
{
	hermon_cfg_profile_t	*cp;

	/*
	 * Allocate space for the configuration profile structure
	 */
	cp = (hermon_cfg_profile_t *)kmem_zalloc(sizeof (hermon_cfg_profile_t),
	    KM_SLEEP);

	/*
	 * Common to all profiles.
	 */
	cp->cp_qp0_agents_in_fw		= hermon_qp0_agents_in_fw;
	cp->cp_qp1_agents_in_fw		= hermon_qp1_agents_in_fw;
	cp->cp_sw_reset_delay		= hermon_sw_reset_delay;
	cp->cp_cmd_poll_delay		= hermon_cmd_poll_delay;
	cp->cp_cmd_poll_max		= hermon_cmd_poll_max;
	cp->cp_ackreq_freq		= hermon_qp_ackreq_freq;
	cp->cp_fmr_max_remaps		= hermon_fmr_num_remaps;

	/*
	 * Although most of the configuration is enabled in "phase2" of the
	 * cfg_profile_init, we have to setup the OUT mailboxes soon, since
	 * they are used immediately after this "phase1" completes, to run the
	 * firmware and get the device limits, which we'll need for 'phase2'.
	 * That's done in rsrc_init_phase1, called shortly after we do this
	 * and the sw reset - see hermon.c
	 */
	if (state->hs_cfg_profile_setting == HERMON_CFG_MEMFREE) {
		cp->cp_log_num_outmbox		= hermon_log_num_outmbox;
		cp->cp_log_outmbox_size		= hermon_log_outmbox_size;
		cp->cp_log_num_inmbox		= hermon_log_num_inmbox;
		cp->cp_log_inmbox_size		= hermon_log_inmbox_size;
		cp->cp_log_num_intr_inmbox	= hermon_log_num_intr_inmbox;
		cp->cp_log_num_intr_outmbox	= hermon_log_num_intr_outmbox;

	} else {
		return (DDI_FAILURE);
	}

	/*
	 * Set IOMMU bypass or not.  Ensure consistency of flags with
	 * architecture type.
	 */
#ifdef __sparc
	if (hermon_iommu_bypass == 1) {
		hermon_check_iommu_bypass(state, cp);
	} else {
		cp->cp_iommu_bypass = HERMON_BINDMEM_NORMAL;
	}
#else
	cp->cp_iommu_bypass = HERMON_BINDMEM_NORMAL;
#endif

	/* Attach the configuration profile to Hermon softstate */
	state->hs_cfg_profile = cp;

	return (DDI_SUCCESS);
}

/*
 * hermon_cfg_profile_init_phase2()
 *    Context: Only called from attach() path context
 */
int
hermon_cfg_profile_init_phase2(hermon_state_t *state)
{
	hermon_cfg_profile_t	*cp;
	hermon_hw_querydevlim_t	*devlim;
	hermon_hw_query_port_t	*port;
	uint32_t		num, size;
	int			i;

	/* Read in the device limits */
	devlim = &state->hs_devlim;
	/* and the port information */
	port = &state->hs_queryport;

	/* Read the configuration profile */
	cp = state->hs_cfg_profile;

	/*
	 * We configure all Hermon HCAs with the same profile, which
	 * is based upon the default value assignments above. If we want to
	 * add additional profiles in the future, they can be added here.
	 * Note the reference to "Memfree" is a holdover from Arbel/Sinai
	 */
	if (state->hs_cfg_profile_setting != HERMON_CFG_MEMFREE) {
		return (DDI_FAILURE);
	}

	/*
	 * Note for most configuration parameters, we use the lesser of our
	 * desired configuration value or the device-defined maximum value.
	 */
	cp->cp_log_num_mtt	= min(hermon_log_num_mtt, devlim->log_max_mtt);
	cp->cp_log_num_dmpt = min(hermon_log_num_dmpt, devlim->log_max_dmpt);
	cp->cp_log_num_cmpt	= HERMON_LOG_CMPT_PER_TYPE + 2;	/* times 4, */
								/* per PRM */
	cp->cp_log_max_mrw_sz	= min(hermon_log_max_mrw_sz,
	    devlim->log_max_mrw_sz);
	cp->cp_log_num_pd	= min(hermon_log_num_pd, devlim->log_max_pd);
	cp->cp_log_num_qp	= min(hermon_log_num_qp, devlim->log_max_qp);
	cp->cp_log_num_cq	= min(hermon_log_num_cq, devlim->log_max_cq);
	cp->cp_log_num_srq	= min(hermon_log_num_srq, devlim->log_max_srq);
	cp->cp_log_num_eq	= min(hermon_log_num_eq, devlim->log_max_eq);
	cp->cp_log_eq_sz	= min(hermon_log_eq_sz, devlim->log_max_eq_sz);
	cp->cp_log_num_rdb	= cp->cp_log_num_qp +
	    min(hermon_log_num_rdb_per_qp, devlim->log_max_ra_req_qp);
	cp->cp_hca_max_rdma_in_qp = cp->cp_hca_max_rdma_out_qp =
	    1 << min(hermon_log_num_rdb_per_qp, devlim->log_max_ra_req_qp);
	cp->cp_num_qp_per_mcg	= max(hermon_num_qp_per_mcg,
	    HERMON_NUM_QP_PER_MCG_MIN);
	cp->cp_num_qp_per_mcg	= min(cp->cp_num_qp_per_mcg,
	    (1 << devlim->log_max_qp_mcg) - 8);
	cp->cp_num_qp_per_mcg	= (1 << highbit(cp->cp_num_qp_per_mcg + 7)) - 8;
	cp->cp_log_num_mcg 	= min(hermon_log_num_mcg, devlim->log_max_mcg);
	cp->cp_log_num_mcg_hash	= hermon_log_num_mcg_hash;

	/* until srq_resize is debugged, disable it */
	cp->cp_srq_resize_enabled = 0;

	/* cp->cp_log_num_uar	= hermon_log_num_uar; */
	/*
	 * now, we HAVE to calculate the number of UAR pages, so that we can
	 * get the blueflame stuff correct as well
	 */

	size = devlim->log_max_uar_sz;
	/* 1MB (2^^20) times size (2^^size) / sparc_pg (2^^13) */
	num = (20 + size) - 13;		/* XXX - consider using PAGESHIFT */
	if (devlim->blu_flm)
		num -= 1;	/* if blueflame, only half the size for UARs */
	cp->cp_log_num_uar	= min(hermon_log_num_uar, num);


	/* while we're at it, calculate the index of the kernel uar page */
	/* either the reserved uar's or 128, whichever is smaller */
	state->hs_kernel_uar_index = (devlim->num_rsvd_uar > 128) ?
	    devlim->num_rsvd_uar : 128;

	cp->cp_log_max_pkeytbl	= port->log_max_pkey;

	cp->cp_log_max_qp_sz	= devlim->log_max_qp_sz;
	cp->cp_log_max_cq_sz	= devlim->log_max_cq_sz;
	cp->cp_log_max_srq_sz	= devlim->log_max_srq_sz;
	cp->cp_log_max_gidtbl	= port->log_max_gid;
	cp->cp_max_mtu		= port->ib_mtu;	/* XXX now from query_port */
	cp->cp_max_port_width	= port->ib_port_wid;  /* now from query_port */
	cp->cp_max_vlcap	= port->max_vl;
	cp->cp_log_num_ah	= hermon_log_num_ah;

	/* Paranoia, ensure no arrays indexed by port_num are out of bounds */
	cp->cp_num_ports	= devlim->num_ports;
	if (cp->cp_num_ports > HERMON_MAX_PORTS) {
		cmn_err(CE_CONT, "device has more ports (%d) than are "
		    "supported; Using %d ports\n",
		    cp->cp_num_ports, HERMON_MAX_PORTS);
		cp->cp_num_ports = HERMON_MAX_PORTS;
	};

	/* allocate variable sized arrays */
	for (i = 0; i < HERMON_MAX_PORTS; i++) {
		state->hs_pkey[i] = kmem_zalloc((1 << cp->cp_log_max_pkeytbl) *
		    sizeof (ib_pkey_t), KM_SLEEP);
		state->hs_guid[i] = kmem_zalloc((1 << cp->cp_log_max_gidtbl) *
		    sizeof (ib_guid_t), KM_SLEEP);
	}

	/* Determine WQE sizes from requested max SGLs */
	hermon_cfg_wqe_sizes(state, cp);

	/* Set whether to use MSIs or not */
	cp->cp_use_msi_if_avail = hermon_use_msi_if_avail;

#if !defined(_ELF64)
	/*
	 * Need to reduce the hermon kernel virtual memory footprint
	 * on 32-bit kernels.
	 */
	cp->cp_log_num_mtt	-= 6;
	cp->cp_log_num_dmpt	-= 6;
	cp->cp_log_num_pd	-= 6;
	cp->cp_log_num_qp	-= 6;
	cp->cp_log_num_cq	-= 6;
	cp->cp_log_num_srq	-= 6;
	cp->cp_log_num_rdb	= cp->cp_log_num_qp +
	    min(hermon_log_num_rdb_per_qp, devlim->log_max_ra_req_qp);
	cp->cp_hca_max_rdma_in_qp = cp->cp_hca_max_rdma_out_qp =
	    1 << min(hermon_log_num_rdb_per_qp, devlim->log_max_ra_req_qp);
#endif

	return (DDI_SUCCESS);
}


/*
 * hermon_cfg_profile_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_cfg_profile_fini(hermon_state_t *state)
{
	/*
	 * Free up the space for configuration profile
	 */
	kmem_free(state->hs_cfg_profile, sizeof (hermon_cfg_profile_t));
}


/*
 * hermon_cfg_wqe_sizes()
 *    Context: Only called from attach() path context
 */
static void
hermon_cfg_wqe_sizes(hermon_state_t *state, hermon_cfg_profile_t *cp)
{
	uint_t	max_size, log2;
	uint_t	max_sgl, real_max_sgl;

	/*
	 * Get the requested maximum number SGL per WQE from the Hermon
	 * patchable variable
	 */
	max_sgl = hermon_wqe_max_sgl;

	/*
	 * Use requested maximum number of SGL to calculate the max descriptor
	 * size (while guaranteeing that the descriptor size is a power-of-2
	 * cachelines).  We have to use the calculation for QP1 MLX transport
	 * because the possibility that we might need to inline a GRH, along
	 * with all the other headers and alignment restrictions, sets the
	 * maximum for the number of SGLs that we can advertise support for.
	 */
	max_size = (HERMON_QP_WQE_MLX_QP1_HDRS + (max_sgl << 4));
	log2 = highbit(max_size);
	if (ISP2(max_size)) {
		log2 = log2 - 1;
	}
	max_size = (1 << log2);

	max_size = min(max_size, state->hs_devlim.max_desc_sz_sq);

	/*
	 * Then use the calculated max descriptor size to determine the "real"
	 * maximum SGL (the number beyond which we would roll over to the next
	 * power-of-2).
	 */
	real_max_sgl = (max_size - HERMON_QP_WQE_MLX_QP1_HDRS) >> 4;

	/* Then save away this configuration information */
	cp->cp_wqe_max_sgl	= max_sgl;
	cp->cp_wqe_real_max_sgl = real_max_sgl;

	/* SRQ SGL gets set to it's own patchable variable value */
	cp->cp_srq_max_sgl		= hermon_srq_max_sgl;
}

#ifdef __sparc
/*
 * hermon_check_iommu_bypass()
 *    Context: Only called from attach() path context
 *    XXX This is a DMA allocation routine outside the normal
 *	  path. FMA hardening will not like this.
 */
static void
hermon_check_iommu_bypass(hermon_state_t *state, hermon_cfg_profile_t *cp)
{
	ddi_dma_handle_t	dmahdl;
	ddi_dma_attr_t		dma_attr;
	int			status;
	ddi_acc_handle_t	acc_hdl;
	caddr_t			kaddr;
	size_t			actual_len;
	ddi_dma_cookie_t	cookie;
	uint_t			cookiecnt;

	hermon_dma_attr_init(state, &dma_attr);

	/* Try mapping for IOMMU bypass (Force Physical) */
	dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL |
	    DDI_DMA_RELAXED_ORDERING;

	/*
	 * Call ddi_dma_alloc_handle().  If this returns DDI_DMA_BADATTR then
	 * it is not possible to use IOMMU bypass with our PCI bridge parent.
	 * Since the function we are in can only be called if iommu bypass was
	 * requested in the config profile, we configure for bypass if the
	 * ddi_dma_alloc_handle() was successful.  Otherwise, we configure
	 * for non-bypass (ie: normal) mapping.
	 */
	status = ddi_dma_alloc_handle(state->hs_dip, &dma_attr,
	    DDI_DMA_SLEEP, NULL, &dmahdl);
	if (status == DDI_DMA_BADATTR) {
		cp->cp_iommu_bypass = HERMON_BINDMEM_NORMAL;
		return;
	} else if (status != DDI_SUCCESS) {	/* failed somehow */
		hermon_kernel_data_ro = HERMON_RO_DISABLED;
		hermon_user_data_ro = HERMON_RO_DISABLED;
		cp->cp_iommu_bypass = HERMON_BINDMEM_BYPASS;
		return;
	} else {
		cp->cp_iommu_bypass = HERMON_BINDMEM_BYPASS;
	}

	status = ddi_dma_mem_alloc(dmahdl, 256,
	    &state->hs_reg_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, (caddr_t *)&kaddr, &actual_len, &acc_hdl);

	if (status != DDI_SUCCESS) {		/* failed somehow */
		hermon_kernel_data_ro = HERMON_RO_DISABLED;
		hermon_user_data_ro = HERMON_RO_DISABLED;
		ddi_dma_free_handle(&dmahdl);
		return;
	}

	status = ddi_dma_addr_bind_handle(dmahdl, NULL, kaddr, actual_len,
	    DDI_DMA_RDWR, DDI_DMA_SLEEP, NULL, &cookie, &cookiecnt);

	if (status == DDI_DMA_MAPPED) {
		(void) ddi_dma_unbind_handle(dmahdl);
	} else {
		hermon_kernel_data_ro = HERMON_RO_DISABLED;
		hermon_user_data_ro = HERMON_RO_DISABLED;
	}

	ddi_dma_mem_free(&acc_hdl);
	ddi_dma_free_handle(&dmahdl);
}
#endif
