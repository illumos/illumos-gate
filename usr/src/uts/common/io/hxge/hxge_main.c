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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SunOs MT STREAMS Hydra 10Gb Ethernet Device Driver.
 */
#include <hxge_impl.h>
#include <hxge_pfc.h>

/*
 * PSARC/2007/453 MSI-X interrupt limit override
 * (This PSARC case is limited to MSI-X vectors
 *  and SPARC platforms only).
 */
#if defined(_BIG_ENDIAN)
uint32_t hxge_msi_enable = 2;
#else
uint32_t hxge_msi_enable = 1;
#endif

/*
 * Globals: tunable parameters (/etc/system or adb)
 *
 */
uint32_t hxge_rbr_size = HXGE_RBR_RBB_DEFAULT;
uint32_t hxge_rbr_spare_size = 0;
uint32_t hxge_rcr_size = HXGE_RCR_DEFAULT;
uint32_t hxge_tx_ring_size = HXGE_TX_RING_DEFAULT;
uint32_t hxge_bcopy_thresh = TX_BCOPY_MAX;
uint32_t hxge_dvma_thresh = TX_FASTDVMA_MIN;
uint32_t hxge_dma_stream_thresh = TX_STREAM_MIN;
uint32_t hxge_jumbo_frame_size = MAX_FRAME_SIZE;

static hxge_os_mutex_t hxgedebuglock;
static int hxge_debug_init = 0;

/*
 * Debugging flags:
 *		hxge_no_tx_lb : transmit load balancing
 *		hxge_tx_lb_policy: 0 - TCP/UDP port (default)
 *				   1 - From the Stack
 *				   2 - Destination IP Address
 */
uint32_t hxge_no_tx_lb = 0;
uint32_t hxge_tx_lb_policy = HXGE_TX_LB_TCPUDP;

/*
 * Add tunable to reduce the amount of time spent in the
 * ISR doing Rx Processing.
 */
uint32_t hxge_max_rx_pkts = 1024;

/*
 * Tunables to manage the receive buffer blocks.
 *
 * hxge_rx_threshold_hi: copy all buffers.
 * hxge_rx_bcopy_size_type: receive buffer block size type.
 * hxge_rx_threshold_lo: copy only up to tunable block size type.
 */
hxge_rxbuf_threshold_t hxge_rx_threshold_hi = HXGE_RX_COPY_6;
hxge_rxbuf_type_t hxge_rx_buf_size_type = RCR_PKTBUFSZ_0;
hxge_rxbuf_threshold_t hxge_rx_threshold_lo = HXGE_RX_COPY_3;

rtrace_t hpi_rtracebuf;

/*
 * Function Prototypes
 */
static int hxge_attach(dev_info_t *, ddi_attach_cmd_t);
static int hxge_detach(dev_info_t *, ddi_detach_cmd_t);
static void hxge_unattach(p_hxge_t);

static hxge_status_t hxge_setup_system_dma_pages(p_hxge_t);

static hxge_status_t hxge_setup_mutexes(p_hxge_t);
static void hxge_destroy_mutexes(p_hxge_t);

static hxge_status_t hxge_map_regs(p_hxge_t hxgep);
static void hxge_unmap_regs(p_hxge_t hxgep);

hxge_status_t hxge_add_intrs(p_hxge_t hxgep);
static hxge_status_t hxge_add_soft_intrs(p_hxge_t hxgep);
static void hxge_remove_intrs(p_hxge_t hxgep);
static void hxge_remove_soft_intrs(p_hxge_t hxgep);
static hxge_status_t hxge_add_intrs_adv(p_hxge_t hxgep);
static hxge_status_t hxge_add_intrs_adv_type(p_hxge_t, uint32_t);
static hxge_status_t hxge_add_intrs_adv_type_fix(p_hxge_t, uint32_t);
void hxge_intrs_enable(p_hxge_t hxgep);
static void hxge_intrs_disable(p_hxge_t hxgep);
static void hxge_suspend(p_hxge_t);
static hxge_status_t hxge_resume(p_hxge_t);
hxge_status_t hxge_setup_dev(p_hxge_t);
static void hxge_destroy_dev(p_hxge_t);
hxge_status_t hxge_alloc_mem_pool(p_hxge_t);
static void hxge_free_mem_pool(p_hxge_t);
static hxge_status_t hxge_alloc_rx_mem_pool(p_hxge_t);
static void hxge_free_rx_mem_pool(p_hxge_t);
static hxge_status_t hxge_alloc_tx_mem_pool(p_hxge_t);
static void hxge_free_tx_mem_pool(p_hxge_t);
static hxge_status_t hxge_dma_mem_alloc(p_hxge_t, dma_method_t,
    struct ddi_dma_attr *, size_t, ddi_device_acc_attr_t *, uint_t,
    p_hxge_dma_common_t);
static void hxge_dma_mem_free(p_hxge_dma_common_t);
static hxge_status_t hxge_alloc_rx_buf_dma(p_hxge_t, uint16_t,
    p_hxge_dma_common_t *, size_t, size_t, uint32_t *);
static void hxge_free_rx_buf_dma(p_hxge_t, p_hxge_dma_common_t, uint32_t);
static hxge_status_t hxge_alloc_rx_cntl_dma(p_hxge_t, uint16_t,
    p_hxge_dma_common_t *, struct ddi_dma_attr *, size_t);
static void hxge_free_rx_cntl_dma(p_hxge_t, p_hxge_dma_common_t);
static hxge_status_t hxge_alloc_tx_buf_dma(p_hxge_t, uint16_t,
    p_hxge_dma_common_t *, size_t, size_t, uint32_t *);
static void hxge_free_tx_buf_dma(p_hxge_t, p_hxge_dma_common_t, uint32_t);
static hxge_status_t hxge_alloc_tx_cntl_dma(p_hxge_t, uint16_t,
    p_hxge_dma_common_t *, size_t);
static void hxge_free_tx_cntl_dma(p_hxge_t, p_hxge_dma_common_t);
static int hxge_init_common_dev(p_hxge_t);
static void hxge_uninit_common_dev(p_hxge_t);

/*
 * The next declarations are for the GLDv3 interface.
 */
static int hxge_m_start(void *);
static void hxge_m_stop(void *);
static int hxge_m_unicst(void *, const uint8_t *);
static int hxge_m_multicst(void *, boolean_t, const uint8_t *);
static int hxge_m_promisc(void *, boolean_t);
static void hxge_m_ioctl(void *, queue_t *, mblk_t *);
static void hxge_m_resources(void *);
static hxge_status_t hxge_mac_register(p_hxge_t hxgep);

static int hxge_m_mmac_add(void *arg, mac_multi_addr_t *maddr);
static int hxge_m_mmac_remove(void *arg, mac_addr_slot_t slot);
static int hxge_m_mmac_modify(void *arg, mac_multi_addr_t *maddr);
static int hxge_m_mmac_get(void *arg, mac_multi_addr_t *maddr);
static boolean_t hxge_m_getcapab(void *, mac_capab_t, void *);
static boolean_t hxge_param_locked(mac_prop_id_t pr_num);
static int hxge_m_setprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val);
static int hxge_m_getprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_flags, uint_t pr_valsize, void *pr_val);
static int hxge_get_def_val(hxge_t *hxgep, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val);
static int hxge_set_priv_prop(p_hxge_t hxgep, const char *pr_name,
    uint_t pr_valsize, const void *pr_val);
static int hxge_get_priv_prop(p_hxge_t hxgep, const char *pr_name,
    uint_t pr_flags, uint_t pr_valsize, void *pr_val);
static void hxge_link_poll(void *arg);
static void hxge_link_update(p_hxge_t hxge, link_state_t state);

mac_priv_prop_t hxge_priv_props[] = {
	{"_rxdma_intr_time", MAC_PROP_PERM_RW},
	{"_rxdma_intr_pkts", MAC_PROP_PERM_RW},
	{"_class_opt_ipv4_tcp", MAC_PROP_PERM_RW},
	{"_class_opt_ipv4_udp", MAC_PROP_PERM_RW},
	{"_class_opt_ipv4_ah", MAC_PROP_PERM_RW},
	{"_class_opt_ipv4_sctp", MAC_PROP_PERM_RW},
	{"_class_opt_ipv6_tcp", MAC_PROP_PERM_RW},
	{"_class_opt_ipv6_udp", MAC_PROP_PERM_RW},
	{"_class_opt_ipv6_ah", MAC_PROP_PERM_RW},
	{"_class_opt_ipv6_sctp", MAC_PROP_PERM_RW}
};

#define	HXGE_MAX_PRIV_PROPS	\
	(sizeof (hxge_priv_props)/sizeof (mac_priv_prop_t))

#define	HXGE_MAGIC	0x4E584745UL
#define	MAX_DUMP_SZ 256

#define	HXGE_M_CALLBACK_FLAGS	\
	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP)

extern mblk_t *hxge_m_tx(void *arg, mblk_t *mp);
extern hxge_status_t hxge_pfc_set_default_mac_addr(p_hxge_t hxgep);

static mac_callbacks_t hxge_m_callbacks = {
	HXGE_M_CALLBACK_FLAGS,
	hxge_m_stat,
	hxge_m_start,
	hxge_m_stop,
	hxge_m_promisc,
	hxge_m_multicst,
	hxge_m_unicst,
	hxge_m_tx,
	hxge_m_resources,
	hxge_m_ioctl,
	hxge_m_getcapab,
	NULL,
	NULL,
	hxge_m_setprop,
	hxge_m_getprop
};

/* Enable debug messages as necessary. */
uint64_t hxge_debug_level = 0;

/*
 * This list contains the instance structures for the Hydra
 * devices present in the system. The lock exists to guarantee
 * mutually exclusive access to the list.
 */
void *hxge_list = NULL;
void *hxge_hw_list = NULL;
hxge_os_mutex_t hxge_common_lock;

extern uint64_t hpi_debug_level;

extern hxge_status_t hxge_ldgv_init();
extern hxge_status_t hxge_ldgv_uninit();
extern hxge_status_t hxge_intr_ldgv_init();
extern void hxge_fm_init(p_hxge_t hxgep, ddi_device_acc_attr_t *reg_attr,
    ddi_device_acc_attr_t *desc_attr, ddi_dma_attr_t *dma_attr);
extern void hxge_fm_fini(p_hxge_t hxgep);

/*
 * Count used to maintain the number of buffers being used
 * by Hydra instances and loaned up to the upper layers.
 */
uint32_t hxge_mblks_pending = 0;

/*
 * Device register access attributes for PIO.
 */
static ddi_device_acc_attr_t hxge_dev_reg_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};

/*
 * Device descriptor access attributes for DMA.
 */
static ddi_device_acc_attr_t hxge_dev_desc_dma_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Device buffer access attributes for DMA.
 */
static ddi_device_acc_attr_t hxge_dev_buf_dma_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC
};

ddi_dma_attr_t hxge_rx_rcr_desc_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
	0x80000,		/* alignment */
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(unsigned int)1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t hxge_tx_desc_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
	0x100000,		/* alignment */
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(unsigned int)1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t hxge_rx_rbr_desc_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
	0x40000,		/* alignment */
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(unsigned int)1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t hxge_rx_mbox_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
#if defined(_BIG_ENDIAN)
	0x2000,			/* alignment */
#else
	0x1000,			/* alignment */
#endif
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	5,			/* scatter/gather list length */
	(unsigned int)1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t hxge_tx_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
#if defined(_BIG_ENDIAN)
	0x2000,			/* alignment */
#else
	0x1000,			/* alignment */
#endif
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	5,			/* scatter/gather list length */
	(unsigned int)1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t hxge_rx_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
	0x10000,		/* alignment */
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(unsigned int)1,	/* granularity */
	DDI_DMA_RELAXED_ORDERING /* attribute flags */
};

ddi_dma_lim_t hxge_dma_limits = {
	(uint_t)0,		/* dlim_addr_lo */
	(uint_t)0xffffffff,	/* dlim_addr_hi */
	(uint_t)0xffffffff,	/* dlim_cntr_max */
	(uint_t)0xfc00fc,	/* dlim_burstsizes for 32 and 64 bit xfers */
	0x1,			/* dlim_minxfer */
	1024			/* dlim_speed */
};

dma_method_t hxge_force_dma = DVMA;

/*
 * dma chunk sizes.
 *
 * Try to allocate the largest possible size
 * so that fewer number of dma chunks would be managed
 */
size_t alloc_sizes[] = {
    0x1000, 0x2000, 0x4000, 0x8000,
    0x10000, 0x20000, 0x40000, 0x80000,
    0x100000, 0x200000, 0x400000, 0x800000, 0x1000000
};

/*
 * Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
static int
hxge_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	p_hxge_t	hxgep = NULL;
	int		instance;
	int		status = DDI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_attach"));

	/*
	 * Get the device instance since we'll need to setup or retrieve a soft
	 * state for this instance.
	 */
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing DDI_ATTACH"));
		break;

	case DDI_RESUME:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing DDI_RESUME"));
		hxgep = (p_hxge_t)ddi_get_soft_state(hxge_list, instance);
		if (hxgep == NULL) {
			status = DDI_FAILURE;
			break;
		}
		if (hxgep->dip != dip) {
			status = DDI_FAILURE;
			break;
		}
		if (hxgep->suspended == DDI_PM_SUSPEND) {
			status = ddi_dev_is_needed(hxgep->dip, 0, 1);
		} else {
			(void) hxge_resume(hxgep);
		}
		goto hxge_attach_exit;

	case DDI_PM_RESUME:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing DDI_PM_RESUME"));
		hxgep = (p_hxge_t)ddi_get_soft_state(hxge_list, instance);
		if (hxgep == NULL) {
			status = DDI_FAILURE;
			break;
		}
		if (hxgep->dip != dip) {
			status = DDI_FAILURE;
			break;
		}
		(void) hxge_resume(hxgep);
		goto hxge_attach_exit;

	default:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing unknown"));
		status = DDI_FAILURE;
		goto hxge_attach_exit;
	}

	if (ddi_soft_state_zalloc(hxge_list, instance) == DDI_FAILURE) {
		status = DDI_FAILURE;
		HXGE_ERROR_MSG((hxgep, DDI_CTL,
		    "ddi_soft_state_zalloc failed"));
		goto hxge_attach_exit;
	}

	hxgep = ddi_get_soft_state(hxge_list, instance);
	if (hxgep == NULL) {
		status = HXGE_ERROR;
		HXGE_ERROR_MSG((hxgep, DDI_CTL,
		    "ddi_get_soft_state failed"));
		goto hxge_attach_fail2;
	}

	hxgep->drv_state = 0;
	hxgep->dip = dip;
	hxgep->instance = instance;
	hxgep->p_dip = ddi_get_parent(dip);
	hxgep->hxge_debug_level = hxge_debug_level;
	hpi_debug_level = hxge_debug_level;

	hxge_fm_init(hxgep, &hxge_dev_reg_acc_attr, &hxge_dev_desc_dma_acc_attr,
	    &hxge_rx_dma_attr);

	status = hxge_map_regs(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "hxge_map_regs failed"));
		goto hxge_attach_fail3;
	}

	status = hxge_init_common_dev(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_init_common_dev failed"));
		goto hxge_attach_fail4;
	}

	/*
	 * Setup the Ndd parameters for this instance.
	 */
	hxge_init_param(hxgep);

	/*
	 * Setup Register Tracing Buffer.
	 */
	hpi_rtrace_buf_init((rtrace_t *)&hpi_rtracebuf);

	/* init stats ptr */
	hxge_init_statsp(hxgep);

	status = hxge_setup_mutexes(hxgep);
	if (status != HXGE_OK) {
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "set mutex failed"));
		goto hxge_attach_fail;
	}

	status = hxge_get_config_properties(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "get_hw create failed"));
		goto hxge_attach_fail;
	}

	/*
	 * Setup the Kstats for the driver.
	 */
	hxge_setup_kstats(hxgep);
	hxge_setup_param(hxgep);

	status = hxge_setup_system_dma_pages(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "set dma page failed"));
		goto hxge_attach_fail;
	}

	hxge_hw_id_init(hxgep);
	hxge_hw_init_niu_common(hxgep);

	status = hxge_setup_dev(hxgep);
	if (status != DDI_SUCCESS) {
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "set dev failed"));
		goto hxge_attach_fail;
	}

	status = hxge_add_intrs(hxgep);
	if (status != DDI_SUCCESS) {
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "add_intr failed"));
		goto hxge_attach_fail;
	}

	status = hxge_add_soft_intrs(hxgep);
	if (status != DDI_SUCCESS) {
		HXGE_DEBUG_MSG((hxgep, HXGE_ERR_CTL, "add_soft_intr failed"));
		goto hxge_attach_fail;
	}

	/*
	 * Enable interrupts.
	 */
	hxge_intrs_enable(hxgep);

	/*
	 * Take off all peu parity error mask here after ddi_intr_enable
	 * is called
	 */
	HXGE_REG_WR32(hxgep->hpi_handle, PEU_INTR_MASK, 0x0);

	if ((status = hxge_mac_register(hxgep)) != HXGE_OK) {
		HXGE_DEBUG_MSG((hxgep, DDI_CTL,
		    "unable to register to mac layer (%d)", status));
		goto hxge_attach_fail;
	}
	mac_link_update(hxgep->mach, LINK_STATE_UNKNOWN);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "registered to mac (instance %d)",
	    instance));

	goto hxge_attach_exit;

hxge_attach_fail:
	hxge_unattach(hxgep);
	goto hxge_attach_fail1;

hxge_attach_fail5:
	/*
	 * Tear down the ndd parameters setup.
	 */
	hxge_destroy_param(hxgep);

	/*
	 * Tear down the kstat setup.
	 */
	hxge_destroy_kstats(hxgep);

hxge_attach_fail4:
	if (hxgep->hxge_hw_p) {
		hxge_uninit_common_dev(hxgep);
		hxgep->hxge_hw_p = NULL;
	}
hxge_attach_fail3:
	/*
	 * Unmap the register setup.
	 */
	hxge_unmap_regs(hxgep);

	hxge_fm_fini(hxgep);

hxge_attach_fail2:
	ddi_soft_state_free(hxge_list, hxgep->instance);

hxge_attach_fail1:
	if (status != HXGE_OK)
		status = (HXGE_ERROR | HXGE_DDI_FAILED);
	hxgep = NULL;

hxge_attach_exit:
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_attach status = 0x%08x",
	    status));

	return (status);
}

static int
hxge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		status = DDI_SUCCESS;
	int		instance;
	p_hxge_t	hxgep = NULL;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_detach"));
	instance = ddi_get_instance(dip);
	hxgep = ddi_get_soft_state(hxge_list, instance);
	if (hxgep == NULL) {
		status = DDI_FAILURE;
		goto hxge_detach_exit;
	}

	switch (cmd) {
	case DDI_DETACH:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing DDI_DETACH"));
		break;

	case DDI_PM_SUSPEND:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing DDI_PM_SUSPEND"));
		hxgep->suspended = DDI_PM_SUSPEND;
		hxge_suspend(hxgep);
		break;

	case DDI_SUSPEND:
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "doing DDI_SUSPEND"));
		if (hxgep->suspended != DDI_PM_SUSPEND) {
			hxgep->suspended = DDI_SUSPEND;
			hxge_suspend(hxgep);
		}
		break;

	default:
		status = DDI_FAILURE;
		break;
	}

	if (cmd != DDI_DETACH)
		goto hxge_detach_exit;

	/*
	 * Stop the xcvr polling.
	 */
	hxgep->suspended = cmd;

	if (hxgep->mach && (status = mac_unregister(hxgep->mach)) != 0) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_detach status = 0x%08X", status));
		return (DDI_FAILURE);
	}
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "<== hxge_detach (mac_unregister) status = 0x%08X", status));

	hxge_unattach(hxgep);
	hxgep = NULL;

hxge_detach_exit:
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_detach status = 0x%08X",
	    status));

	return (status);
}

static void
hxge_unattach(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_unattach"));

	if (hxgep == NULL || hxgep->dev_regs == NULL) {
		return;
	}

	if (hxgep->hxge_hw_p) {
		hxge_uninit_common_dev(hxgep);
		hxgep->hxge_hw_p = NULL;
	}

	if (hxgep->hxge_timerid) {
		hxge_stop_timer(hxgep, hxgep->hxge_timerid);
		hxgep->hxge_timerid = 0;
	}

	/* Stop any further interrupts. */
	hxge_remove_intrs(hxgep);

	/* Remove soft interrups */
	hxge_remove_soft_intrs(hxgep);

	/* Stop the device and free resources. */
	hxge_destroy_dev(hxgep);

	/* Tear down the ndd parameters setup. */
	hxge_destroy_param(hxgep);

	/* Tear down the kstat setup. */
	hxge_destroy_kstats(hxgep);

	/*
	 * Remove the list of ndd parameters which were setup during attach.
	 */
	if (hxgep->dip) {
		HXGE_DEBUG_MSG((hxgep, OBP_CTL,
		    " hxge_unattach: remove all properties"));
		(void) ddi_prop_remove_all(hxgep->dip);
	}

	/*
	 * Reset RDC, TDC, PFC, and VMAC blocks from PEU to clear any
	 * previous state before unmapping the registers.
	 */
	HXGE_REG_WR32(hxgep->hpi_handle, BLOCK_RESET, 0x0000001E);
	HXGE_DELAY(1000);

	/*
	 * Unmap the register setup.
	 */
	hxge_unmap_regs(hxgep);

	hxge_fm_fini(hxgep);

	/* Destroy all mutexes.  */
	hxge_destroy_mutexes(hxgep);

	/*
	 * Free the soft state data structures allocated with this instance.
	 */
	ddi_soft_state_free(hxge_list, hxgep->instance);

	HXGE_DEBUG_MSG((NULL, DDI_CTL, "<== hxge_unattach"));
}

static hxge_status_t
hxge_map_regs(p_hxge_t hxgep)
{
	int		ddi_status = DDI_SUCCESS;
	p_dev_regs_t	dev_regs;

#ifdef	HXGE_DEBUG
	char		*sysname;
#endif

	off_t		regsize;
	hxge_status_t	status = HXGE_OK;
	int		nregs;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_map_regs"));

	if (ddi_dev_nregs(hxgep->dip, &nregs) != DDI_SUCCESS)
		return (HXGE_ERROR);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "hxge_map_regs: nregs: %d", nregs));

	hxgep->dev_regs = NULL;
	dev_regs = KMEM_ZALLOC(sizeof (dev_regs_t), KM_SLEEP);
	dev_regs->hxge_regh = NULL;
	dev_regs->hxge_pciregh = NULL;
	dev_regs->hxge_msix_regh = NULL;

	(void) ddi_dev_regsize(hxgep->dip, 0, &regsize);
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "hxge_map_regs: pci config size 0x%x", regsize));

	ddi_status = ddi_regs_map_setup(hxgep->dip, 0,
	    (caddr_t *)&(dev_regs->hxge_pciregp), 0, 0,
	    &hxge_dev_reg_acc_attr, &dev_regs->hxge_pciregh);
	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_map_regs, hxge bus config regs failed"));
		goto hxge_map_regs_fail0;
	}

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "hxge_map_reg: PCI config addr 0x%0llx handle 0x%0llx",
	    dev_regs->hxge_pciregp,
	    dev_regs->hxge_pciregh));

	(void) ddi_dev_regsize(hxgep->dip, 1, &regsize);
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "hxge_map_regs: pio size 0x%x", regsize));

	/* set up the device mapped register */
	ddi_status = ddi_regs_map_setup(hxgep->dip, 1,
	    (caddr_t *)&(dev_regs->hxge_regp), 0, 0,
	    &hxge_dev_reg_acc_attr, &dev_regs->hxge_regh);

	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_map_regs for Hydra global reg failed"));
		goto hxge_map_regs_fail1;
	}

	/* set up the msi/msi-x mapped register */
	(void) ddi_dev_regsize(hxgep->dip, 2, &regsize);
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "hxge_map_regs: msix size 0x%x", regsize));

	ddi_status = ddi_regs_map_setup(hxgep->dip, 2,
	    (caddr_t *)&(dev_regs->hxge_msix_regp), 0, 0,
	    &hxge_dev_reg_acc_attr, &dev_regs->hxge_msix_regh);

	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_map_regs for msi reg failed"));
		goto hxge_map_regs_fail2;
	}

	hxgep->dev_regs = dev_regs;

	HPI_PCI_ACC_HANDLE_SET(hxgep, dev_regs->hxge_pciregh);
	HPI_PCI_ADD_HANDLE_SET(hxgep, (hpi_reg_ptr_t)dev_regs->hxge_pciregp);
	HPI_MSI_ACC_HANDLE_SET(hxgep, dev_regs->hxge_msix_regh);
	HPI_MSI_ADD_HANDLE_SET(hxgep, (hpi_reg_ptr_t)dev_regs->hxge_msix_regp);

	HPI_ACC_HANDLE_SET(hxgep, dev_regs->hxge_regh);
	HPI_ADD_HANDLE_SET(hxgep, (hpi_reg_ptr_t)dev_regs->hxge_regp);

	HPI_REG_ACC_HANDLE_SET(hxgep, dev_regs->hxge_regh);
	HPI_REG_ADD_HANDLE_SET(hxgep, (hpi_reg_ptr_t)dev_regs->hxge_regp);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "hxge_map_reg: hardware addr 0x%0llx "
	    " handle 0x%0llx", dev_regs->hxge_regp, dev_regs->hxge_regh));

	goto hxge_map_regs_exit;

hxge_map_regs_fail3:
	if (dev_regs->hxge_msix_regh) {
		ddi_regs_map_free(&dev_regs->hxge_msix_regh);
	}

hxge_map_regs_fail2:
	if (dev_regs->hxge_regh) {
		ddi_regs_map_free(&dev_regs->hxge_regh);
	}

hxge_map_regs_fail1:
	if (dev_regs->hxge_pciregh) {
		ddi_regs_map_free(&dev_regs->hxge_pciregh);
	}

hxge_map_regs_fail0:
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "Freeing register set memory"));
	kmem_free(dev_regs, sizeof (dev_regs_t));

hxge_map_regs_exit:
	if (ddi_status != DDI_SUCCESS)
		status |= (HXGE_ERROR | HXGE_DDI_FAILED);
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_map_regs"));
	return (status);
}

static void
hxge_unmap_regs(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_unmap_regs"));
	if (hxgep->dev_regs) {
		if (hxgep->dev_regs->hxge_pciregh) {
			HXGE_DEBUG_MSG((hxgep, DDI_CTL,
			    "==> hxge_unmap_regs: bus"));
			ddi_regs_map_free(&hxgep->dev_regs->hxge_pciregh);
			hxgep->dev_regs->hxge_pciregh = NULL;
		}

		if (hxgep->dev_regs->hxge_regh) {
			HXGE_DEBUG_MSG((hxgep, DDI_CTL,
			    "==> hxge_unmap_regs: device registers"));
			ddi_regs_map_free(&hxgep->dev_regs->hxge_regh);
			hxgep->dev_regs->hxge_regh = NULL;
		}

		if (hxgep->dev_regs->hxge_msix_regh) {
			HXGE_DEBUG_MSG((hxgep, DDI_CTL,
			    "==> hxge_unmap_regs: device interrupts"));
			ddi_regs_map_free(&hxgep->dev_regs->hxge_msix_regh);
			hxgep->dev_regs->hxge_msix_regh = NULL;
		}
		kmem_free(hxgep->dev_regs, sizeof (dev_regs_t));
		hxgep->dev_regs = NULL;
	}
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_unmap_regs"));
}

static hxge_status_t
hxge_setup_mutexes(p_hxge_t hxgep)
{
	int		ddi_status = DDI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_setup_mutexes"));

	/*
	 * Get the interrupt cookie so the mutexes can be Initialised.
	 */
	ddi_status = ddi_get_iblock_cookie(hxgep->dip, 0,
	    &hxgep->interrupt_cookie);

	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_setup_mutexes: failed 0x%x", ddi_status));
		goto hxge_setup_mutexes_exit;
	}

	/*
	 * Initialize mutex's for this device.
	 */
	MUTEX_INIT(hxgep->genlock, NULL,
	    MUTEX_DRIVER, (void *) hxgep->interrupt_cookie);
	MUTEX_INIT(&hxgep->ouraddr_lock, NULL,
	    MUTEX_DRIVER, (void *) hxgep->interrupt_cookie);
	RW_INIT(&hxgep->filter_lock, NULL,
	    RW_DRIVER, (void *) hxgep->interrupt_cookie);
	MUTEX_INIT(&hxgep->pio_lock, NULL,
	    MUTEX_DRIVER, (void *) hxgep->interrupt_cookie);
	MUTEX_INIT(&hxgep->timeout.lock, NULL,
	    MUTEX_DRIVER, (void *) hxgep->interrupt_cookie);

hxge_setup_mutexes_exit:
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "<== hxge_setup_mutexes status = %x", status));

	if (ddi_status != DDI_SUCCESS)
		status |= (HXGE_ERROR | HXGE_DDI_FAILED);

	return (status);
}

static void
hxge_destroy_mutexes(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_destroy_mutexes"));
	RW_DESTROY(&hxgep->filter_lock);
	MUTEX_DESTROY(&hxgep->ouraddr_lock);
	MUTEX_DESTROY(hxgep->genlock);
	MUTEX_DESTROY(&hxgep->pio_lock);
	MUTEX_DESTROY(&hxgep->timeout.lock);

	if (hxge_debug_init == 1) {
		MUTEX_DESTROY(&hxgedebuglock);
		hxge_debug_init = 0;
	}

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_destroy_mutexes"));
}

hxge_status_t
hxge_init(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, STR_CTL, "==> hxge_init"));

	if (hxgep->drv_state & STATE_HW_INITIALIZED) {
		return (status);
	}

	/*
	 * Allocate system memory for the receive/transmit buffer blocks and
	 * receive/transmit descriptor rings.
	 */
	status = hxge_alloc_mem_pool(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "alloc mem failed\n"));
		goto hxge_init_fail1;
	}

	/*
	 * Initialize and enable TXDMA channels.
	 */
	status = hxge_init_txdma_channels(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "init txdma failed\n"));
		goto hxge_init_fail3;
	}

	/*
	 * Initialize and enable RXDMA channels.
	 */
	status = hxge_init_rxdma_channels(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "init rxdma failed\n"));
		goto hxge_init_fail4;
	}

	/*
	 * Initialize TCAM
	 */
	status = hxge_classify_init(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "init classify failed\n"));
		goto hxge_init_fail5;
	}

	/*
	 * Initialize the VMAC block.
	 */
	status = hxge_vmac_init(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "init MAC failed\n"));
		goto hxge_init_fail5;
	}

	/* Bringup - this may be unnecessary when PXE and FCODE available */
	status = hxge_pfc_set_default_mac_addr(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "Default Address Failure\n"));
		goto hxge_init_fail5;
	}

	hxge_intrs_enable(hxgep);

	/*
	 * Enable hardware interrupts.
	 */
	hxge_intr_hw_enable(hxgep);
	hxgep->drv_state |= STATE_HW_INITIALIZED;

	goto hxge_init_exit;

hxge_init_fail5:
	hxge_uninit_rxdma_channels(hxgep);
hxge_init_fail4:
	hxge_uninit_txdma_channels(hxgep);
hxge_init_fail3:
	hxge_free_mem_pool(hxgep);
hxge_init_fail1:
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "<== hxge_init status (failed) = 0x%08x", status));
	return (status);

hxge_init_exit:

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_init status = 0x%08x",
	    status));

	return (status);
}

timeout_id_t
hxge_start_timer(p_hxge_t hxgep, fptrv_t func, int msec)
{
	if ((hxgep->suspended == 0) || (hxgep->suspended == DDI_RESUME)) {
		return (timeout(func, (caddr_t)hxgep,
		    drv_usectohz(1000 * msec)));
	}
	return (NULL);
}

/*ARGSUSED*/
void
hxge_stop_timer(p_hxge_t hxgep, timeout_id_t timerid)
{
	if (timerid) {
		(void) untimeout(timerid);
	}
}

void
hxge_uninit(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_uninit"));

	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		HXGE_DEBUG_MSG((hxgep, DDI_CTL,
		    "==> hxge_uninit: not initialized"));
		HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_uninit"));
		return;
	}

	/* Stop timer */
	if (hxgep->hxge_timerid) {
		hxge_stop_timer(hxgep, hxgep->hxge_timerid);
		hxgep->hxge_timerid = 0;
	}

	(void) hxge_intr_hw_disable(hxgep);

	/* Reset the receive VMAC side.  */
	(void) hxge_rx_vmac_disable(hxgep);

	/* Free classification resources */
	(void) hxge_classify_uninit(hxgep);

	/* Reset the transmit/receive DMA side.  */
	(void) hxge_txdma_hw_mode(hxgep, HXGE_DMA_STOP);
	(void) hxge_rxdma_hw_mode(hxgep, HXGE_DMA_STOP);

	hxge_uninit_txdma_channels(hxgep);
	hxge_uninit_rxdma_channels(hxgep);

	/* Reset the transmit VMAC side.  */
	(void) hxge_tx_vmac_disable(hxgep);

	hxge_free_mem_pool(hxgep);

	hxgep->drv_state &= ~STATE_HW_INITIALIZED;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_uninit"));
}

void
hxge_get64(p_hxge_t hxgep, p_mblk_t mp)
{
#if defined(__i386)
	size_t		reg;
#else
	uint64_t	reg;
#endif
	uint64_t	regdata;
	int		i, retry;

	bcopy((char *)mp->b_rptr, (char *)&reg, sizeof (uint64_t));
	regdata = 0;
	retry = 1;

	for (i = 0; i < retry; i++) {
		HXGE_REG_RD64(hxgep->hpi_handle, reg, &regdata);
	}
	bcopy((char *)&regdata, (char *)mp->b_rptr, sizeof (uint64_t));
}

void
hxge_put64(p_hxge_t hxgep, p_mblk_t mp)
{
#if defined(__i386)
	size_t		reg;
#else
	uint64_t	reg;
#endif
	uint64_t	buf[2];

	bcopy((char *)mp->b_rptr, (char *)&buf[0], 2 * sizeof (uint64_t));
#if defined(__i386)
	reg = (size_t)buf[0];
#else
	reg = buf[0];
#endif

	HXGE_HPI_PIO_WRITE64(hxgep->hpi_handle, reg, buf[1]);
}

/*ARGSUSED*/
/*VARARGS*/
void
hxge_debug_msg(p_hxge_t hxgep, uint64_t level, char *fmt, ...)
{
	char		msg_buffer[1048];
	char		prefix_buffer[32];
	int		instance;
	uint64_t	debug_level;
	int		cmn_level = CE_CONT;
	va_list		ap;

	debug_level = (hxgep == NULL) ? hxge_debug_level :
	    hxgep->hxge_debug_level;

	if ((level & debug_level) || (level == HXGE_NOTE) ||
	    (level == HXGE_ERR_CTL)) {
		/* do the msg processing */
		if (hxge_debug_init == 0) {
			MUTEX_INIT(&hxgedebuglock, NULL, MUTEX_DRIVER, NULL);
			hxge_debug_init = 1;
		}

		MUTEX_ENTER(&hxgedebuglock);

		if ((level & HXGE_NOTE)) {
			cmn_level = CE_NOTE;
		}

		if (level & HXGE_ERR_CTL) {
			cmn_level = CE_WARN;
		}

		va_start(ap, fmt);
		(void) vsprintf(msg_buffer, fmt, ap);
		va_end(ap);

		if (hxgep == NULL) {
			instance = -1;
			(void) sprintf(prefix_buffer, "%s :", "hxge");
		} else {
			instance = hxgep->instance;
			(void) sprintf(prefix_buffer,
			    "%s%d :", "hxge", instance);
		}

		MUTEX_EXIT(&hxgedebuglock);
		cmn_err(cmn_level, "%s %s\n", prefix_buffer, msg_buffer);
	}
}

char *
hxge_dump_packet(char *addr, int size)
{
	uchar_t		*ap = (uchar_t *)addr;
	int		i;
	static char	etherbuf[1024];
	char		*cp = etherbuf;
	char		digits[] = "0123456789abcdef";

	if (!size)
		size = 60;

	if (size > MAX_DUMP_SZ) {
		/* Dump the leading bytes */
		for (i = 0; i < MAX_DUMP_SZ / 2; i++) {
			if (*ap > 0x0f)
				*cp++ = digits[*ap >> 4];
			*cp++ = digits[*ap++ & 0xf];
			*cp++ = ':';
		}
		for (i = 0; i < 20; i++)
			*cp++ = '.';
		/* Dump the last MAX_DUMP_SZ/2 bytes */
		ap = (uchar_t *)(addr + (size - MAX_DUMP_SZ / 2));
		for (i = 0; i < MAX_DUMP_SZ / 2; i++) {
			if (*ap > 0x0f)
				*cp++ = digits[*ap >> 4];
			*cp++ = digits[*ap++ & 0xf];
			*cp++ = ':';
		}
	} else {
		for (i = 0; i < size; i++) {
			if (*ap > 0x0f)
				*cp++ = digits[*ap >> 4];
			*cp++ = digits[*ap++ & 0xf];
			*cp++ = ':';
		}
	}
	*--cp = 0;
	return (etherbuf);
}

static void
hxge_suspend(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_suspend"));

	hxge_intrs_disable(hxgep);
	hxge_destroy_dev(hxgep);

	/* Stop the link status timer */
	MUTEX_ENTER(&hxgep->timeout.lock);
	if (hxgep->timeout.id)
		(void) untimeout(hxgep->timeout.id);
	MUTEX_EXIT(&hxgep->timeout.lock);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_suspend"));
}

static hxge_status_t
hxge_resume(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_resume"));
	hxgep->suspended = DDI_RESUME;

	(void) hxge_rxdma_hw_mode(hxgep, HXGE_DMA_START);
	(void) hxge_txdma_hw_mode(hxgep, HXGE_DMA_START);

	(void) hxge_rx_vmac_enable(hxgep);
	(void) hxge_tx_vmac_enable(hxgep);

	hxge_intrs_enable(hxgep);

	hxgep->suspended = 0;

	/* Resume the link status timer */
	MUTEX_ENTER(&hxgep->timeout.lock);
	hxgep->timeout.id = timeout(hxge_link_poll, (void *)hxgep,
	    hxgep->timeout.ticks);
	MUTEX_EXIT(&hxgep->timeout.lock);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "<== hxge_resume status = 0x%x", status));

	return (status);
}

hxge_status_t
hxge_setup_dev(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_setup_dev"));

	status = hxge_link_init(hxgep);
	if (fm_check_acc_handle(hxgep->dev_regs->hxge_regh) != DDI_FM_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "Bad register acc handle"));
		status = HXGE_ERROR;
	}

	if (status != HXGE_OK) {
		HXGE_DEBUG_MSG((hxgep, MAC_CTL,
		    " hxge_setup_dev status (link init 0x%08x)", status));
		goto hxge_setup_dev_exit;
	}

hxge_setup_dev_exit:
	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "<== hxge_setup_dev status = 0x%08x", status));

	return (status);
}

static void
hxge_destroy_dev(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_destroy_dev"));

	(void) hxge_hw_stop(hxgep);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_destroy_dev"));
}

static hxge_status_t
hxge_setup_system_dma_pages(p_hxge_t hxgep)
{
	int			ddi_status = DDI_SUCCESS;
	uint_t			count;
	ddi_dma_cookie_t	cookie;
	uint_t			iommu_pagesize;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_setup_system_dma_pages"));

	hxgep->sys_page_sz = ddi_ptob(hxgep->dip, (ulong_t)1);
	iommu_pagesize = dvma_pagesize(hxgep->dip);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    " hxge_setup_system_dma_pages: page %d (ddi_ptob %d) "
	    " default_block_size %d iommu_pagesize %d",
	    hxgep->sys_page_sz, ddi_ptob(hxgep->dip, (ulong_t)1),
	    hxgep->rx_default_block_size, iommu_pagesize));

	if (iommu_pagesize != 0) {
		if (hxgep->sys_page_sz == iommu_pagesize) {
			/* Hydra support up to 8K pages */
			if (iommu_pagesize > 0x2000)
				hxgep->sys_page_sz = 0x2000;
		} else {
			if (hxgep->sys_page_sz > iommu_pagesize)
				hxgep->sys_page_sz = iommu_pagesize;
		}
	}

	hxgep->sys_page_mask = ~(hxgep->sys_page_sz - 1);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "==> hxge_setup_system_dma_pages: page %d (ddi_ptob %d) "
	    "default_block_size %d page mask %d",
	    hxgep->sys_page_sz, ddi_ptob(hxgep->dip, (ulong_t)1),
	    hxgep->rx_default_block_size, hxgep->sys_page_mask));

	switch (hxgep->sys_page_sz) {
	default:
		hxgep->sys_page_sz = 0x1000;
		hxgep->sys_page_mask = ~(hxgep->sys_page_sz - 1);
		hxgep->rx_default_block_size = 0x1000;
		hxgep->rx_bksize_code = RBR_BKSIZE_4K;
		break;
	case 0x1000:
		hxgep->rx_default_block_size = 0x1000;
		hxgep->rx_bksize_code = RBR_BKSIZE_4K;
		break;
	case 0x2000:
		hxgep->rx_default_block_size = 0x2000;
		hxgep->rx_bksize_code = RBR_BKSIZE_8K;
		break;
	}

	hxge_rx_dma_attr.dma_attr_align = hxgep->sys_page_sz;
	hxge_tx_dma_attr.dma_attr_align = hxgep->sys_page_sz;

	/*
	 * Get the system DMA burst size.
	 */
	ddi_status = ddi_dma_alloc_handle(hxgep->dip, &hxge_tx_dma_attr,
	    DDI_DMA_DONTWAIT, 0, &hxgep->dmasparehandle);
	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_dma_alloc_handle: failed status 0x%x", ddi_status));
		goto hxge_get_soft_properties_exit;
	}

	ddi_status = ddi_dma_addr_bind_handle(hxgep->dmasparehandle, NULL,
	    (caddr_t)hxgep->dmasparehandle, sizeof (hxgep->dmasparehandle),
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, 0,
	    &cookie, &count);
	if (ddi_status != DDI_DMA_MAPPED) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "Binding spare handle to find system burstsize failed."));
		ddi_status = DDI_FAILURE;
		goto hxge_get_soft_properties_fail1;
	}

	hxgep->sys_burst_sz = ddi_dma_burstsizes(hxgep->dmasparehandle);
	(void) ddi_dma_unbind_handle(hxgep->dmasparehandle);

hxge_get_soft_properties_fail1:
	ddi_dma_free_handle(&hxgep->dmasparehandle);

hxge_get_soft_properties_exit:

	if (ddi_status != DDI_SUCCESS)
		status |= (HXGE_ERROR | HXGE_DDI_FAILED);

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "<== hxge_setup_system_dma_pages status = 0x%08x", status));

	return (status);
}

hxge_status_t
hxge_alloc_mem_pool(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_alloc_mem_pool"));

	status = hxge_alloc_rx_mem_pool(hxgep);
	if (status != HXGE_OK) {
		return (HXGE_ERROR);
	}

	status = hxge_alloc_tx_mem_pool(hxgep);
	if (status != HXGE_OK) {
		hxge_free_rx_mem_pool(hxgep);
		return (HXGE_ERROR);
	}

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_alloc_mem_pool"));
	return (HXGE_OK);
}

static void
hxge_free_mem_pool(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, MEM_CTL, "==> hxge_free_mem_pool"));

	hxge_free_rx_mem_pool(hxgep);
	hxge_free_tx_mem_pool(hxgep);

	HXGE_DEBUG_MSG((hxgep, MEM_CTL, "<== hxge_free_mem_pool"));
}

static hxge_status_t
hxge_alloc_rx_mem_pool(p_hxge_t hxgep)
{
	int			i, j;
	uint32_t		ndmas, st_rdc;
	p_hxge_dma_pt_cfg_t	p_all_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	p_hxge_dma_pool_t	dma_poolp;
	p_hxge_dma_common_t	*dma_buf_p;
	p_hxge_dma_pool_t	dma_rbr_cntl_poolp;
	p_hxge_dma_common_t	*dma_rbr_cntl_p;
	p_hxge_dma_pool_t	dma_rcr_cntl_poolp;
	p_hxge_dma_common_t	*dma_rcr_cntl_p;
	p_hxge_dma_pool_t	dma_mbox_cntl_poolp;
	p_hxge_dma_common_t	*dma_mbox_cntl_p;
	size_t			rx_buf_alloc_size;
	size_t			rx_rbr_cntl_alloc_size;
	size_t			rx_rcr_cntl_alloc_size;
	size_t			rx_mbox_cntl_alloc_size;
	uint32_t		*num_chunks;	/* per dma */
	hxge_status_t		status = HXGE_OK;

	uint32_t		hxge_port_rbr_size;
	uint32_t		hxge_port_rbr_spare_size;
	uint32_t		hxge_port_rcr_size;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_alloc_rx_mem_pool"));

	p_all_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;
	st_rdc = p_cfgp->start_rdc;
	ndmas = p_cfgp->max_rdcs;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    " hxge_alloc_rx_mem_pool st_rdc %d ndmas %d", st_rdc, ndmas));

	/*
	 * Allocate memory for each receive DMA channel.
	 */
	dma_poolp = (p_hxge_dma_pool_t)KMEM_ZALLOC(sizeof (hxge_dma_pool_t),
	    KM_SLEEP);
	dma_buf_p = (p_hxge_dma_common_t *)KMEM_ZALLOC(
	    sizeof (p_hxge_dma_common_t) * ndmas, KM_SLEEP);

	dma_rbr_cntl_poolp = (p_hxge_dma_pool_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_pool_t), KM_SLEEP);
	dma_rbr_cntl_p = (p_hxge_dma_common_t *)KMEM_ZALLOC(
	    sizeof (p_hxge_dma_common_t) * ndmas, KM_SLEEP);
	dma_rcr_cntl_poolp = (p_hxge_dma_pool_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_pool_t), KM_SLEEP);
	dma_rcr_cntl_p = (p_hxge_dma_common_t *)KMEM_ZALLOC(
	    sizeof (p_hxge_dma_common_t) * ndmas, KM_SLEEP);
	dma_mbox_cntl_poolp = (p_hxge_dma_pool_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_pool_t), KM_SLEEP);
	dma_mbox_cntl_p = (p_hxge_dma_common_t *)KMEM_ZALLOC(
	    sizeof (p_hxge_dma_common_t) * ndmas, KM_SLEEP);

	num_chunks = (uint32_t *)KMEM_ZALLOC(sizeof (uint32_t) * ndmas,
	    KM_SLEEP);

	/*
	 * Assume that each DMA channel will be configured with default block
	 * size. rbr block counts are mod of batch count (16).
	 */
	hxge_port_rbr_size = p_all_cfgp->rbr_size;
	hxge_port_rcr_size = p_all_cfgp->rcr_size;

	if (!hxge_port_rbr_size) {
		hxge_port_rbr_size = HXGE_RBR_RBB_DEFAULT;
	}

	if (hxge_port_rbr_size % HXGE_RXDMA_POST_BATCH) {
		hxge_port_rbr_size = (HXGE_RXDMA_POST_BATCH *
		    (hxge_port_rbr_size / HXGE_RXDMA_POST_BATCH + 1));
	}

	p_all_cfgp->rbr_size = hxge_port_rbr_size;
	hxge_port_rbr_spare_size = hxge_rbr_spare_size;

	if (hxge_port_rbr_spare_size % HXGE_RXDMA_POST_BATCH) {
		hxge_port_rbr_spare_size = (HXGE_RXDMA_POST_BATCH *
		    (hxge_port_rbr_spare_size / HXGE_RXDMA_POST_BATCH + 1));
	}

	rx_buf_alloc_size = (hxgep->rx_default_block_size *
	    (hxge_port_rbr_size + hxge_port_rbr_spare_size));

	/*
	 * Addresses of receive block ring, receive completion ring and the
	 * mailbox must be all cache-aligned (64 bytes).
	 */
	rx_rbr_cntl_alloc_size = hxge_port_rbr_size + hxge_port_rbr_spare_size;
	rx_rbr_cntl_alloc_size *= sizeof (rx_desc_t);
	rx_rcr_cntl_alloc_size = sizeof (rcr_entry_t) * hxge_port_rcr_size;
	rx_mbox_cntl_alloc_size = sizeof (rxdma_mailbox_t);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_alloc_rx_mem_pool: "
	    "hxge_port_rbr_size = %d hxge_port_rbr_spare_size = %d "
	    "hxge_port_rcr_size = %d rx_cntl_alloc_size = %d",
	    hxge_port_rbr_size, hxge_port_rbr_spare_size,
	    hxge_port_rcr_size, rx_cntl_alloc_size));

	hxgep->hxge_port_rbr_size = hxge_port_rbr_size;
	hxgep->hxge_port_rcr_size = hxge_port_rcr_size;

	/*
	 * Allocate memory for receive buffers and descriptor rings. Replace
	 * allocation functions with interface functions provided by the
	 * partition manager when it is available.
	 */
	/*
	 * Allocate memory for the receive buffer blocks.
	 */
	for (i = 0; i < ndmas; i++) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    " hxge_alloc_rx_mem_pool to alloc mem: "
		    " dma %d dma_buf_p %llx &dma_buf_p %llx",
		    i, dma_buf_p[i], &dma_buf_p[i]));

		num_chunks[i] = 0;

		status = hxge_alloc_rx_buf_dma(hxgep, st_rdc, &dma_buf_p[i],
		    rx_buf_alloc_size, hxgep->rx_default_block_size,
		    &num_chunks[i]);
		if (status != HXGE_OK) {
			break;
		}

		st_rdc++;
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    " hxge_alloc_rx_mem_pool DONE  alloc mem: "
		    "dma %d dma_buf_p %llx &dma_buf_p %llx", i,
		    dma_buf_p[i], &dma_buf_p[i]));
	}

	if (i < ndmas) {
		goto hxge_alloc_rx_mem_fail1;
	}

	/*
	 * Allocate memory for descriptor rings and mailbox.
	 */
	st_rdc = p_cfgp->start_rdc;
	for (j = 0; j < ndmas; j++) {
		if ((status = hxge_alloc_rx_cntl_dma(hxgep, st_rdc,
		    &dma_rbr_cntl_p[j], &hxge_rx_rbr_desc_dma_attr,
		    rx_rbr_cntl_alloc_size)) != HXGE_OK) {
			break;
		}

		if ((status = hxge_alloc_rx_cntl_dma(hxgep, st_rdc,
		    &dma_rcr_cntl_p[j], &hxge_rx_rcr_desc_dma_attr,
		    rx_rcr_cntl_alloc_size)) != HXGE_OK) {
			break;
		}

		if ((status = hxge_alloc_rx_cntl_dma(hxgep, st_rdc,
		    &dma_mbox_cntl_p[j], &hxge_rx_mbox_dma_attr,
		    rx_mbox_cntl_alloc_size)) != HXGE_OK) {
			break;
		}
		st_rdc++;
	}

	if (j < ndmas) {
		goto hxge_alloc_rx_mem_fail2;
	}

	dma_poolp->ndmas = ndmas;
	dma_poolp->num_chunks = num_chunks;
	dma_poolp->buf_allocated = B_TRUE;
	hxgep->rx_buf_pool_p = dma_poolp;
	dma_poolp->dma_buf_pool_p = dma_buf_p;

	dma_rbr_cntl_poolp->ndmas = ndmas;
	dma_rbr_cntl_poolp->buf_allocated = B_TRUE;
	hxgep->rx_rbr_cntl_pool_p = dma_rbr_cntl_poolp;
	dma_rbr_cntl_poolp->dma_buf_pool_p = dma_rbr_cntl_p;

	dma_rcr_cntl_poolp->ndmas = ndmas;
	dma_rcr_cntl_poolp->buf_allocated = B_TRUE;
	hxgep->rx_rcr_cntl_pool_p = dma_rcr_cntl_poolp;
	dma_rcr_cntl_poolp->dma_buf_pool_p = dma_rcr_cntl_p;

	dma_mbox_cntl_poolp->ndmas = ndmas;
	dma_mbox_cntl_poolp->buf_allocated = B_TRUE;
	hxgep->rx_mbox_cntl_pool_p = dma_mbox_cntl_poolp;
	dma_mbox_cntl_poolp->dma_buf_pool_p = dma_mbox_cntl_p;

	goto hxge_alloc_rx_mem_pool_exit;

hxge_alloc_rx_mem_fail2:
	/* Free control buffers */
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_alloc_rx_mem_pool: freeing control bufs (%d)", j));
	for (; j >= 0; j--) {
		hxge_free_rx_cntl_dma(hxgep,
		    (p_hxge_dma_common_t)dma_rbr_cntl_p[j]);
		hxge_free_rx_cntl_dma(hxgep,
		    (p_hxge_dma_common_t)dma_rcr_cntl_p[j]);
		hxge_free_rx_cntl_dma(hxgep,
		    (p_hxge_dma_common_t)dma_mbox_cntl_p[j]);
		HXGE_DEBUG_MSG((hxgep, DMA_CTL,
		    "==> hxge_alloc_rx_mem_pool: control bufs freed (%d)", j));
	}
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_alloc_rx_mem_pool: control bufs freed (%d)", j));

hxge_alloc_rx_mem_fail1:
	/* Free data buffers */
	i--;
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_alloc_rx_mem_pool: freeing data bufs (%d)", i));
	for (; i >= 0; i--) {
		hxge_free_rx_buf_dma(hxgep, (p_hxge_dma_common_t)dma_buf_p[i],
		    num_chunks[i]);
	}
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_alloc_rx_mem_pool: data bufs freed (%d)", i));

	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);
	KMEM_FREE(dma_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_rbr_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_rbr_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_rcr_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_rcr_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_mbox_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_mbox_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));

hxge_alloc_rx_mem_pool_exit:
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_alloc_rx_mem_pool:status 0x%08x", status));

	return (status);
}

static void
hxge_free_rx_mem_pool(p_hxge_t hxgep)
{
	uint32_t		i, ndmas;
	p_hxge_dma_pool_t	dma_poolp;
	p_hxge_dma_common_t	*dma_buf_p;
	p_hxge_dma_pool_t	dma_rbr_cntl_poolp;
	p_hxge_dma_common_t	*dma_rbr_cntl_p;
	p_hxge_dma_pool_t	dma_rcr_cntl_poolp;
	p_hxge_dma_common_t	*dma_rcr_cntl_p;
	p_hxge_dma_pool_t	dma_mbox_cntl_poolp;
	p_hxge_dma_common_t	*dma_mbox_cntl_p;
	uint32_t		*num_chunks;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_free_rx_mem_pool"));

	dma_poolp = hxgep->rx_buf_pool_p;
	if (dma_poolp == NULL || (!dma_poolp->buf_allocated)) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_free_rx_mem_pool "
		    "(null rx buf pool or buf not allocated"));
		return;
	}

	dma_rbr_cntl_poolp = hxgep->rx_rbr_cntl_pool_p;
	if (dma_rbr_cntl_poolp == NULL ||
	    (!dma_rbr_cntl_poolp->buf_allocated)) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "<== hxge_free_rx_mem_pool "
		    "(null rbr cntl buf pool or rbr cntl buf not allocated"));
		return;
	}

	dma_rcr_cntl_poolp = hxgep->rx_rcr_cntl_pool_p;
	if (dma_rcr_cntl_poolp == NULL ||
	    (!dma_rcr_cntl_poolp->buf_allocated)) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "<== hxge_free_rx_mem_pool "
		    "(null rcr cntl buf pool or rcr cntl buf not allocated"));
		return;
	}

	dma_mbox_cntl_poolp = hxgep->rx_mbox_cntl_pool_p;
	if (dma_mbox_cntl_poolp == NULL ||
	    (!dma_mbox_cntl_poolp->buf_allocated)) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "<== hxge_free_rx_mem_pool "
		    "(null mbox cntl buf pool or mbox cntl buf not allocated"));
		return;
	}

	dma_buf_p = dma_poolp->dma_buf_pool_p;
	num_chunks = dma_poolp->num_chunks;

	dma_rbr_cntl_p = dma_rbr_cntl_poolp->dma_buf_pool_p;
	dma_rcr_cntl_p = dma_rcr_cntl_poolp->dma_buf_pool_p;
	dma_mbox_cntl_p = dma_mbox_cntl_poolp->dma_buf_pool_p;
	ndmas = dma_rbr_cntl_poolp->ndmas;

	for (i = 0; i < ndmas; i++) {
		hxge_free_rx_buf_dma(hxgep, dma_buf_p[i], num_chunks[i]);
	}

	for (i = 0; i < ndmas; i++) {
		hxge_free_rx_cntl_dma(hxgep, dma_rbr_cntl_p[i]);
		hxge_free_rx_cntl_dma(hxgep, dma_rcr_cntl_p[i]);
		hxge_free_rx_cntl_dma(hxgep, dma_mbox_cntl_p[i]);
	}

	for (i = 0; i < ndmas; i++) {
		KMEM_FREE(dma_buf_p[i],
		    sizeof (hxge_dma_common_t) * HXGE_DMA_BLOCK);
		KMEM_FREE(dma_rbr_cntl_p[i], sizeof (hxge_dma_common_t));
		KMEM_FREE(dma_rcr_cntl_p[i], sizeof (hxge_dma_common_t));
		KMEM_FREE(dma_mbox_cntl_p[i], sizeof (hxge_dma_common_t));
	}

	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);
	KMEM_FREE(dma_rbr_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_rbr_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_rcr_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_rcr_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_mbox_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_mbox_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_poolp, sizeof (hxge_dma_pool_t));

	hxgep->rx_buf_pool_p = NULL;
	hxgep->rx_rbr_cntl_pool_p = NULL;
	hxgep->rx_rcr_cntl_pool_p = NULL;
	hxgep->rx_mbox_cntl_pool_p = NULL;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_free_rx_mem_pool"));
}

static hxge_status_t
hxge_alloc_rx_buf_dma(p_hxge_t hxgep, uint16_t dma_channel,
    p_hxge_dma_common_t *dmap,
    size_t alloc_size, size_t block_size, uint32_t *num_chunks)
{
	p_hxge_dma_common_t	rx_dmap;
	hxge_status_t		status = HXGE_OK;
	size_t			total_alloc_size;
	size_t			allocated = 0;
	int			i, size_index, array_size;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_alloc_rx_buf_dma"));

	rx_dmap = (p_hxge_dma_common_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_common_t) * HXGE_DMA_BLOCK, KM_SLEEP);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    " alloc_rx_buf_dma rdc %d asize %x bsize %x bbuf %llx ",
	    dma_channel, alloc_size, block_size, dmap));

	total_alloc_size = alloc_size;

	i = 0;
	size_index = 0;
	array_size = sizeof (alloc_sizes) / sizeof (size_t);
	while ((alloc_sizes[size_index] < alloc_size) &&
	    (size_index < array_size))
		size_index++;
	if (size_index >= array_size) {
		size_index = array_size - 1;
	}

	while ((allocated < total_alloc_size) &&
	    (size_index >= 0) && (i < HXGE_DMA_BLOCK)) {
		rx_dmap[i].dma_chunk_index = i;
		rx_dmap[i].block_size = block_size;
		rx_dmap[i].alength = alloc_sizes[size_index];
		rx_dmap[i].orig_alength = rx_dmap[i].alength;
		rx_dmap[i].nblocks = alloc_sizes[size_index] / block_size;
		rx_dmap[i].dma_channel = dma_channel;
		rx_dmap[i].contig_alloc_type = B_FALSE;

		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "alloc_rx_buf_dma rdc %d chunk %d bufp %llx size %x "
		    "i %d nblocks %d alength %d",
		    dma_channel, i, &rx_dmap[i], block_size,
		    i, rx_dmap[i].nblocks, rx_dmap[i].alength));
		status = hxge_dma_mem_alloc(hxgep, hxge_force_dma,
		    &hxge_rx_dma_attr, rx_dmap[i].alength,
		    &hxge_dev_buf_dma_acc_attr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    (p_hxge_dma_common_t)(&rx_dmap[i]));
		if (status != HXGE_OK) {
			HXGE_DEBUG_MSG((hxgep, DMA_CTL,
			    " hxge_alloc_rx_buf_dma: Alloc Failed: "
			    " for size: %d", alloc_sizes[size_index]));
			size_index--;
		} else {
			HXGE_DEBUG_MSG((hxgep, DMA_CTL,
			    " alloc_rx_buf_dma allocated rdc %d "
			    "chunk %d size %x dvma %x bufp %llx ",
			    dma_channel, i, rx_dmap[i].alength,
			    rx_dmap[i].ioaddr_pp, &rx_dmap[i]));
			i++;
			allocated += alloc_sizes[size_index];
		}
	}

	if (allocated < total_alloc_size) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_alloc_rx_buf_dma failed due to"
		    " allocated(%d) < required(%d)",
		    allocated, total_alloc_size));
		goto hxge_alloc_rx_mem_fail1;
	}

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    " alloc_rx_buf_dma rdc %d allocated %d chunks", dma_channel, i));

	*num_chunks = i;
	*dmap = rx_dmap;

	goto hxge_alloc_rx_mem_exit;

hxge_alloc_rx_mem_fail1:
	KMEM_FREE(rx_dmap, sizeof (hxge_dma_common_t) * HXGE_DMA_BLOCK);

hxge_alloc_rx_mem_exit:
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_alloc_rx_buf_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
hxge_free_rx_buf_dma(p_hxge_t hxgep, p_hxge_dma_common_t dmap,
    uint32_t num_chunks)
{
	int i;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_free_rx_buf_dma: # of chunks %d", num_chunks));

	for (i = 0; i < num_chunks; i++) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "==> hxge_free_rx_buf_dma: chunk %d dmap 0x%llx", i, dmap));
		hxge_dma_mem_free(dmap++);
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_free_rx_buf_dma"));
}

/*ARGSUSED*/
static hxge_status_t
hxge_alloc_rx_cntl_dma(p_hxge_t hxgep, uint16_t dma_channel,
    p_hxge_dma_common_t *dmap, struct ddi_dma_attr *attr, size_t size)
{
	p_hxge_dma_common_t	rx_dmap;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_alloc_rx_cntl_dma"));

	rx_dmap = (p_hxge_dma_common_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_common_t), KM_SLEEP);

	rx_dmap->contig_alloc_type = B_FALSE;

	status = hxge_dma_mem_alloc(hxgep, hxge_force_dma,
	    attr, size, &hxge_dev_desc_dma_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, rx_dmap);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_alloc_rx_cntl_dma: Alloc Failed: "
		    " for size: %d", size));
		goto hxge_alloc_rx_cntl_dma_fail1;
	}

	*dmap = rx_dmap;

	goto hxge_alloc_rx_cntl_dma_exit;

hxge_alloc_rx_cntl_dma_fail1:
	KMEM_FREE(rx_dmap, sizeof (hxge_dma_common_t));

hxge_alloc_rx_cntl_dma_exit:
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_alloc_rx_cntl_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
hxge_free_rx_cntl_dma(p_hxge_t hxgep, p_hxge_dma_common_t dmap)
{
	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_free_rx_cntl_dma"));

	hxge_dma_mem_free(dmap);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_free_rx_cntl_dma"));
}

static hxge_status_t
hxge_alloc_tx_mem_pool(p_hxge_t hxgep)
{
	hxge_status_t		status = HXGE_OK;
	int			i, j;
	uint32_t		ndmas, st_tdc;
	p_hxge_dma_pt_cfg_t	p_all_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	p_hxge_dma_pool_t	dma_poolp;
	p_hxge_dma_common_t	*dma_buf_p;
	p_hxge_dma_pool_t	dma_cntl_poolp;
	p_hxge_dma_common_t	*dma_cntl_p;
	size_t			tx_buf_alloc_size;
	size_t			tx_cntl_alloc_size;
	uint32_t		*num_chunks;	/* per dma */

	HXGE_DEBUG_MSG((hxgep, MEM_CTL, "==> hxge_alloc_tx_mem_pool"));

	p_all_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;
	st_tdc = p_cfgp->start_tdc;
	ndmas = p_cfgp->max_tdcs;

	HXGE_DEBUG_MSG((hxgep, MEM_CTL, "==> hxge_alloc_tx_mem_pool: "
	    "p_cfgp 0x%016llx start_tdc %d ndmas %d hxgep->max_tdcs %d",
	    p_cfgp, p_cfgp->start_tdc, p_cfgp->max_tdcs, hxgep->max_tdcs));
	/*
	 * Allocate memory for each transmit DMA channel.
	 */
	dma_poolp = (p_hxge_dma_pool_t)KMEM_ZALLOC(sizeof (hxge_dma_pool_t),
	    KM_SLEEP);
	dma_buf_p = (p_hxge_dma_common_t *)KMEM_ZALLOC(
	    sizeof (p_hxge_dma_common_t) * ndmas, KM_SLEEP);

	dma_cntl_poolp = (p_hxge_dma_pool_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_pool_t), KM_SLEEP);
	dma_cntl_p = (p_hxge_dma_common_t *)KMEM_ZALLOC(
	    sizeof (p_hxge_dma_common_t) * ndmas, KM_SLEEP);

	hxgep->hxge_port_tx_ring_size = hxge_tx_ring_size;

	/*
	 * Assume that each DMA channel will be configured with default
	 * transmit bufer size for copying transmit data. (For packet payload
	 * over this limit, packets will not be copied.)
	 */
	tx_buf_alloc_size = (hxge_bcopy_thresh * hxge_tx_ring_size);

	/*
	 * Addresses of transmit descriptor ring and the mailbox must be all
	 * cache-aligned (64 bytes).
	 */
	tx_cntl_alloc_size = hxge_tx_ring_size;
	tx_cntl_alloc_size *= (sizeof (tx_desc_t));
	tx_cntl_alloc_size += sizeof (txdma_mailbox_t);

	num_chunks = (uint32_t *)KMEM_ZALLOC(sizeof (uint32_t) * ndmas,
	    KM_SLEEP);

	/*
	 * Allocate memory for transmit buffers and descriptor rings. Replace
	 * allocation functions with interface functions provided by the
	 * partition manager when it is available.
	 *
	 * Allocate memory for the transmit buffer pool.
	 */
	for (i = 0; i < ndmas; i++) {
		num_chunks[i] = 0;
		status = hxge_alloc_tx_buf_dma(hxgep, st_tdc, &dma_buf_p[i],
		    tx_buf_alloc_size, hxge_bcopy_thresh, &num_chunks[i]);
		if (status != HXGE_OK) {
			break;
		}
		st_tdc++;
	}

	if (i < ndmas) {
		goto hxge_alloc_tx_mem_pool_fail1;
	}

	st_tdc = p_cfgp->start_tdc;

	/*
	 * Allocate memory for descriptor rings and mailbox.
	 */
	for (j = 0; j < ndmas; j++) {
		status = hxge_alloc_tx_cntl_dma(hxgep, st_tdc, &dma_cntl_p[j],
		    tx_cntl_alloc_size);
		if (status != HXGE_OK) {
			break;
		}
		st_tdc++;
	}

	if (j < ndmas) {
		goto hxge_alloc_tx_mem_pool_fail2;
	}

	dma_poolp->ndmas = ndmas;
	dma_poolp->num_chunks = num_chunks;
	dma_poolp->buf_allocated = B_TRUE;
	dma_poolp->dma_buf_pool_p = dma_buf_p;
	hxgep->tx_buf_pool_p = dma_poolp;

	dma_cntl_poolp->ndmas = ndmas;
	dma_cntl_poolp->buf_allocated = B_TRUE;
	dma_cntl_poolp->dma_buf_pool_p = dma_cntl_p;
	hxgep->tx_cntl_pool_p = dma_cntl_poolp;

	HXGE_DEBUG_MSG((hxgep, MEM_CTL,
	    "==> hxge_alloc_tx_mem_pool: start_tdc %d "
	    "ndmas %d poolp->ndmas %d", st_tdc, ndmas, dma_poolp->ndmas));

	goto hxge_alloc_tx_mem_pool_exit;

hxge_alloc_tx_mem_pool_fail2:
	/* Free control buffers */
	j--;
	for (; j >= 0; j--) {
		hxge_free_tx_cntl_dma(hxgep,
		    (p_hxge_dma_common_t)dma_cntl_p[j]);
	}

hxge_alloc_tx_mem_pool_fail1:
	/* Free data buffers */
	i--;
	for (; i >= 0; i--) {
		hxge_free_tx_buf_dma(hxgep, (p_hxge_dma_common_t)dma_buf_p[i],
		    num_chunks[i]);
	}

	KMEM_FREE(dma_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);

hxge_alloc_tx_mem_pool_exit:
	HXGE_DEBUG_MSG((hxgep, MEM_CTL,
	    "<== hxge_alloc_tx_mem_pool:status 0x%08x", status));

	return (status);
}

static hxge_status_t
hxge_alloc_tx_buf_dma(p_hxge_t hxgep, uint16_t dma_channel,
    p_hxge_dma_common_t *dmap, size_t alloc_size,
    size_t block_size, uint32_t *num_chunks)
{
	p_hxge_dma_common_t	tx_dmap;
	hxge_status_t		status = HXGE_OK;
	size_t			total_alloc_size;
	size_t			allocated = 0;
	int			i, size_index, array_size;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_alloc_tx_buf_dma"));

	tx_dmap = (p_hxge_dma_common_t)
	    KMEM_ZALLOC(sizeof (hxge_dma_common_t) * HXGE_DMA_BLOCK, KM_SLEEP);

	total_alloc_size = alloc_size;
	i = 0;
	size_index = 0;
	array_size = sizeof (alloc_sizes) / sizeof (size_t);
	while ((alloc_sizes[size_index] < alloc_size) &&
	    (size_index < array_size))
		size_index++;
	if (size_index >= array_size) {
		size_index = array_size - 1;
	}

	while ((allocated < total_alloc_size) &&
	    (size_index >= 0) && (i < HXGE_DMA_BLOCK)) {
		tx_dmap[i].dma_chunk_index = i;
		tx_dmap[i].block_size = block_size;
		tx_dmap[i].alength = alloc_sizes[size_index];
		tx_dmap[i].orig_alength = tx_dmap[i].alength;
		tx_dmap[i].nblocks = alloc_sizes[size_index] / block_size;
		tx_dmap[i].dma_channel = dma_channel;
		tx_dmap[i].contig_alloc_type = B_FALSE;

		status = hxge_dma_mem_alloc(hxgep, hxge_force_dma,
		    &hxge_tx_dma_attr, tx_dmap[i].alength,
		    &hxge_dev_buf_dma_acc_attr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    (p_hxge_dma_common_t)(&tx_dmap[i]));
		if (status != HXGE_OK) {
			HXGE_DEBUG_MSG((hxgep, DMA_CTL,
			    " hxge_alloc_tx_buf_dma: Alloc Failed: "
			    " for size: %d", alloc_sizes[size_index]));
			size_index--;
		} else {
			i++;
			allocated += alloc_sizes[size_index];
		}
	}

	if (allocated < total_alloc_size) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_alloc_tx_buf_dma: failed due to"
		    " allocated(%d) < required(%d)",
		    allocated, total_alloc_size));
		goto hxge_alloc_tx_mem_fail1;
	}

	*num_chunks = i;
	*dmap = tx_dmap;
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_alloc_tx_buf_dma dmap 0x%016llx num chunks %d",
	    *dmap, i));
	goto hxge_alloc_tx_mem_exit;

hxge_alloc_tx_mem_fail1:
	KMEM_FREE(tx_dmap, sizeof (hxge_dma_common_t) * HXGE_DMA_BLOCK);

hxge_alloc_tx_mem_exit:
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_alloc_tx_buf_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
hxge_free_tx_buf_dma(p_hxge_t hxgep, p_hxge_dma_common_t dmap,
    uint32_t num_chunks)
{
	int i;

	HXGE_DEBUG_MSG((hxgep, MEM_CTL, "==> hxge_free_tx_buf_dma"));

	for (i = 0; i < num_chunks; i++) {
		hxge_dma_mem_free(dmap++);
	}

	HXGE_DEBUG_MSG((hxgep, MEM_CTL, "<== hxge_free_tx_buf_dma"));
}

/*ARGSUSED*/
static hxge_status_t
hxge_alloc_tx_cntl_dma(p_hxge_t hxgep, uint16_t dma_channel,
    p_hxge_dma_common_t *dmap, size_t size)
{
	p_hxge_dma_common_t	tx_dmap;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_alloc_tx_cntl_dma"));

	tx_dmap = (p_hxge_dma_common_t)KMEM_ZALLOC(sizeof (hxge_dma_common_t),
	    KM_SLEEP);

	tx_dmap->contig_alloc_type = B_FALSE;

	status = hxge_dma_mem_alloc(hxgep, hxge_force_dma,
	    &hxge_tx_desc_dma_attr, size, &hxge_dev_desc_dma_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, tx_dmap);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_alloc_tx_cntl_dma: Alloc Failed: "
		    " for size: %d", size));
		goto hxge_alloc_tx_cntl_dma_fail1;
	}

	*dmap = tx_dmap;

	goto hxge_alloc_tx_cntl_dma_exit;

hxge_alloc_tx_cntl_dma_fail1:
	KMEM_FREE(tx_dmap, sizeof (hxge_dma_common_t));

hxge_alloc_tx_cntl_dma_exit:
	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_alloc_tx_cntl_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
hxge_free_tx_cntl_dma(p_hxge_t hxgep, p_hxge_dma_common_t dmap)
{
	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_free_tx_cntl_dma"));

	hxge_dma_mem_free(dmap);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_free_tx_cntl_dma"));
}

static void
hxge_free_tx_mem_pool(p_hxge_t hxgep)
{
	uint32_t		i, ndmas;
	p_hxge_dma_pool_t	dma_poolp;
	p_hxge_dma_common_t	*dma_buf_p;
	p_hxge_dma_pool_t	dma_cntl_poolp;
	p_hxge_dma_common_t	*dma_cntl_p;
	uint32_t		*num_chunks;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_free_tx_mem_pool"));

	dma_poolp = hxgep->tx_buf_pool_p;
	if (dma_poolp == NULL || (!dma_poolp->buf_allocated)) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_free_tx_mem_pool "
		    "(null rx buf pool or buf not allocated"));
		return;
	}

	dma_cntl_poolp = hxgep->tx_cntl_pool_p;
	if (dma_cntl_poolp == NULL || (!dma_cntl_poolp->buf_allocated)) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_free_tx_mem_pool "
		    "(null tx cntl buf pool or cntl buf not allocated"));
		return;
	}

	dma_buf_p = dma_poolp->dma_buf_pool_p;
	num_chunks = dma_poolp->num_chunks;

	dma_cntl_p = dma_cntl_poolp->dma_buf_pool_p;
	ndmas = dma_cntl_poolp->ndmas;

	for (i = 0; i < ndmas; i++) {
		hxge_free_tx_buf_dma(hxgep, dma_buf_p[i], num_chunks[i]);
	}

	for (i = 0; i < ndmas; i++) {
		hxge_free_tx_cntl_dma(hxgep, dma_cntl_p[i]);
	}

	for (i = 0; i < ndmas; i++) {
		KMEM_FREE(dma_buf_p[i],
		    sizeof (hxge_dma_common_t) * HXGE_DMA_BLOCK);
		KMEM_FREE(dma_cntl_p[i], sizeof (hxge_dma_common_t));
	}

	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);
	KMEM_FREE(dma_cntl_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_cntl_poolp, sizeof (hxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_hxge_dma_common_t));
	KMEM_FREE(dma_poolp, sizeof (hxge_dma_pool_t));

	hxgep->tx_buf_pool_p = NULL;
	hxgep->tx_cntl_pool_p = NULL;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_free_tx_mem_pool"));
}

/*ARGSUSED*/
static hxge_status_t
hxge_dma_mem_alloc(p_hxge_t hxgep, dma_method_t method,
    struct ddi_dma_attr *dma_attrp,
    size_t length, ddi_device_acc_attr_t *acc_attr_p, uint_t xfer_flags,
    p_hxge_dma_common_t dma_p)
{
	caddr_t		kaddrp;
	int		ddi_status = DDI_SUCCESS;

	dma_p->dma_handle = NULL;
	dma_p->acc_handle = NULL;
	dma_p->kaddrp = NULL;

	ddi_status = ddi_dma_alloc_handle(hxgep->dip, dma_attrp,
	    DDI_DMA_DONTWAIT, NULL, &dma_p->dma_handle);
	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_dma_mem_alloc:ddi_dma_alloc_handle failed."));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	ddi_status = ddi_dma_mem_alloc(dma_p->dma_handle, length, acc_attr_p,
	    xfer_flags, DDI_DMA_DONTWAIT, 0, &kaddrp, &dma_p->alength,
	    &dma_p->acc_handle);
	if (ddi_status != DDI_SUCCESS) {
		/* The caller will decide whether it is fatal */
		HXGE_DEBUG_MSG((hxgep, DMA_CTL,
		    "hxge_dma_mem_alloc:ddi_dma_mem_alloc failed"));
		ddi_dma_free_handle(&dma_p->dma_handle);
		dma_p->dma_handle = NULL;
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	if (dma_p->alength < length) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_dma_mem_alloc:ddi_dma_mem_alloc < length."));
		ddi_dma_mem_free(&dma_p->acc_handle);
		ddi_dma_free_handle(&dma_p->dma_handle);
		dma_p->acc_handle = NULL;
		dma_p->dma_handle = NULL;
		return (HXGE_ERROR);
	}

	ddi_status = ddi_dma_addr_bind_handle(dma_p->dma_handle, NULL,
	    kaddrp, dma_p->alength, xfer_flags, DDI_DMA_DONTWAIT, 0,
	    &dma_p->dma_cookie, &dma_p->ncookies);
	if (ddi_status != DDI_DMA_MAPPED) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_dma_mem_alloc:di_dma_addr_bind failed "
		    "(staus 0x%x ncookies %d.)", ddi_status, dma_p->ncookies));
		if (dma_p->acc_handle) {
			ddi_dma_mem_free(&dma_p->acc_handle);
			dma_p->acc_handle = NULL;
		}
		ddi_dma_free_handle(&dma_p->dma_handle);
		dma_p->dma_handle = NULL;
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	if (dma_p->ncookies != 1) {
		HXGE_DEBUG_MSG((hxgep, DMA_CTL,
		    "hxge_dma_mem_alloc:ddi_dma_addr_bind > 1 cookie"
		    "(staus 0x%x ncookies %d.)", ddi_status, dma_p->ncookies));
		if (dma_p->acc_handle) {
			ddi_dma_mem_free(&dma_p->acc_handle);
			dma_p->acc_handle = NULL;
		}
		(void) ddi_dma_unbind_handle(dma_p->dma_handle);
		ddi_dma_free_handle(&dma_p->dma_handle);
		dma_p->dma_handle = NULL;
		return (HXGE_ERROR);
	}

	dma_p->kaddrp = kaddrp;
#if defined(__i386)
	dma_p->ioaddr_pp =
	    (unsigned char *)(uint32_t)dma_p->dma_cookie.dmac_laddress;
#else
	dma_p->ioaddr_pp = (unsigned char *) dma_p->dma_cookie.dmac_laddress;
#endif

	HPI_DMA_ACC_HANDLE_SET(dma_p, dma_p->acc_handle);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_dma_mem_alloc: "
	    "dma buffer allocated: dma_p $%p "
	    "return dmac_ladress from cookie $%p dmac_size %d "
	    "dma_p->ioaddr_p $%p "
	    "dma_p->orig_ioaddr_p $%p "
	    "orig_vatopa $%p "
	    "alength %d (0x%x) "
	    "kaddrp $%p "
	    "length %d (0x%x)",
	    dma_p,
	    dma_p->dma_cookie.dmac_laddress,
	    dma_p->dma_cookie.dmac_size,
	    dma_p->ioaddr_pp,
	    dma_p->orig_ioaddr_pp,
	    dma_p->orig_vatopa,
	    dma_p->alength, dma_p->alength,
	    kaddrp,
	    length, length));

	return (HXGE_OK);
}

static void
hxge_dma_mem_free(p_hxge_dma_common_t dma_p)
{
	if (dma_p == NULL)
		return;

	if (dma_p->dma_handle != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_handle);
			dma_p->ncookies = 0;
		}
		ddi_dma_free_handle(&dma_p->dma_handle);
		dma_p->dma_handle = NULL;
	}

	if (dma_p->acc_handle != NULL) {
		ddi_dma_mem_free(&dma_p->acc_handle);
		dma_p->acc_handle = NULL;
		HPI_DMA_ACC_HANDLE_SET(dma_p, NULL);
	}

	dma_p->kaddrp = NULL;
	dma_p->alength = NULL;
}

/*
 *	hxge_m_start() -- start transmitting and receiving.
 *
 *	This function is called by the MAC layer when the first
 *	stream is open to prepare the hardware ready for sending
 *	and transmitting packets.
 */
static int
hxge_m_start(void *arg)
{
	p_hxge_t hxgep = (p_hxge_t)arg;

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "==> hxge_m_start"));

	MUTEX_ENTER(hxgep->genlock);

	if (hxge_init(hxgep) != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_m_start: initialization failed"));
		MUTEX_EXIT(hxgep->genlock);
		return (EIO);
	}

	if (hxgep->hxge_mac_state != HXGE_MAC_STARTED) {
		/*
		 * Start timer to check the system error and tx hangs
		 */
		hxgep->hxge_timerid = hxge_start_timer(hxgep,
		    hxge_check_hw_state, HXGE_CHECK_TIMER);

		hxgep->hxge_mac_state = HXGE_MAC_STARTED;

		hxgep->timeout.link_status = 0;
		hxgep->timeout.report_link_status = B_TRUE;
		hxgep->timeout.ticks = drv_usectohz(2 * 1000000);

		/* Start the link status timer to check the link status */
		MUTEX_ENTER(&hxgep->timeout.lock);
		hxgep->timeout.id = timeout(hxge_link_poll, (void *)hxgep,
		    hxgep->timeout.ticks);
		MUTEX_EXIT(&hxgep->timeout.lock);
	}

	MUTEX_EXIT(hxgep->genlock);

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "<== hxge_m_start"));

	return (0);
}

/*
 * hxge_m_stop(): stop transmitting and receiving.
 */
static void
hxge_m_stop(void *arg)
{
	p_hxge_t hxgep = (p_hxge_t)arg;

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "==> hxge_m_stop"));

	if (hxgep->hxge_timerid) {
		hxge_stop_timer(hxgep, hxgep->hxge_timerid);
		hxgep->hxge_timerid = 0;
	}

	/* Stop the link status timer before unregistering */
	MUTEX_ENTER(&hxgep->timeout.lock);
	if (hxgep->timeout.id) {
		(void) untimeout(hxgep->timeout.id);
		hxgep->timeout.id = 0;
	}
	hxge_link_update(hxgep, LINK_STATE_DOWN);
	MUTEX_EXIT(&hxgep->timeout.lock);

	MUTEX_ENTER(hxgep->genlock);

	hxge_uninit(hxgep);

	hxgep->hxge_mac_state = HXGE_MAC_STOPPED;

	MUTEX_EXIT(hxgep->genlock);

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "<== hxge_m_stop"));
}

static int
hxge_m_unicst(void *arg, const uint8_t *macaddr)
{
	p_hxge_t		hxgep = (p_hxge_t)arg;
	struct ether_addr	addrp;
	hxge_status_t		status;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_m_unicst"));

	bcopy(macaddr, (uint8_t *)&addrp, ETHERADDRL);

	status = hxge_set_mac_addr(hxgep, &addrp);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_m_unicst: set unitcast failed"));
		return (EINVAL);
	}

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_m_unicst"));

	return (0);
}

static int
hxge_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	p_hxge_t		hxgep = (p_hxge_t)arg;
	struct ether_addr	addrp;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_m_multicst: add %d", add));

	bcopy(mca, (uint8_t *)&addrp, ETHERADDRL);

	if (add) {
		if (hxge_add_mcast_addr(hxgep, &addrp)) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "<== hxge_m_multicst: add multicast failed"));
			return (EINVAL);
		}
	} else {
		if (hxge_del_mcast_addr(hxgep, &addrp)) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "<== hxge_m_multicst: del multicast failed"));
			return (EINVAL);
		}
	}

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_m_multicst"));

	return (0);
}

static int
hxge_m_promisc(void *arg, boolean_t on)
{
	p_hxge_t hxgep = (p_hxge_t)arg;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_m_promisc: on %d", on));

	if (hxge_set_promisc(hxgep, on)) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_m_promisc: set promisc failed"));
		return (EINVAL);
	}

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_m_promisc: on %d", on));

	return (0);
}

static void
hxge_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	p_hxge_t	hxgep = (p_hxge_t)arg;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	boolean_t	need_privilege;
	int		err;
	int		cmd;

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "==> hxge_m_ioctl"));

	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	need_privilege = B_TRUE;
	cmd = iocp->ioc_cmd;

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "==> hxge_m_ioctl: cmd 0x%08x", cmd));
	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "<== hxge_m_ioctl: invalid"));
		return;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
		need_privilege = B_FALSE;
		break;

	case LB_SET_MODE:
		break;

	case ND_GET:
		need_privilege = B_FALSE;
		break;
	case ND_SET:
		break;

	case HXGE_GET64:
	case HXGE_PUT64:
	case HXGE_GET_TX_RING_SZ:
	case HXGE_GET_TX_DESC:
	case HXGE_TX_SIDE_RESET:
	case HXGE_RX_SIDE_RESET:
	case HXGE_GLOBAL_RESET:
	case HXGE_RESET_MAC:
	case HXGE_PUT_TCAM:
	case HXGE_GET_TCAM:
	case HXGE_RTRACE:

		need_privilege = B_FALSE;
		break;
	}

	if (need_privilege) {
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "<== hxge_m_ioctl: no priv"));
			return;
		}
	}

	switch (cmd) {
	case ND_GET:
		HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "ND_GET command"));
	case ND_SET:
		HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "ND_SET command"));
		hxge_param_ioctl(hxgep, wq, mp, iocp);
		break;

	case LB_GET_MODE:
	case LB_SET_MODE:
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
		hxge_loopback_ioctl(hxgep, wq, mp, iocp);
		break;

	case HXGE_PUT_TCAM:
	case HXGE_GET_TCAM:
	case HXGE_GET64:
	case HXGE_PUT64:
	case HXGE_GET_TX_RING_SZ:
	case HXGE_GET_TX_DESC:
	case HXGE_TX_SIDE_RESET:
	case HXGE_RX_SIDE_RESET:
	case HXGE_GLOBAL_RESET:
	case HXGE_RESET_MAC:
		HXGE_DEBUG_MSG((hxgep, NEMO_CTL,
		    "==> hxge_m_ioctl: cmd 0x%x", cmd));
		hxge_hw_ioctl(hxgep, wq, mp, iocp);
		break;
	}

	HXGE_DEBUG_MSG((hxgep, NEMO_CTL, "<== hxge_m_ioctl"));
}

extern void hxge_rx_hw_blank(void *arg, time_t ticks, uint_t count);

static void
hxge_m_resources(void *arg)
{
	p_hxge_t hxgep = arg;
	mac_rx_fifo_t mrf;
	p_rx_rcr_rings_t rcr_rings;
	p_rx_rcr_ring_t *rcr_p;
	p_rx_rcr_ring_t rcrp;
	uint32_t i, ndmas;
	int status;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_m_resources"));

	MUTEX_ENTER(hxgep->genlock);

	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = hxge_init(hxgep);
		if (status != HXGE_OK) {
			HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_m_resources: "
			    "hxge_init failed"));
			MUTEX_EXIT(hxgep->genlock);
			return;
		}
	}

	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = hxge_rx_hw_blank;
	mrf.mrf_arg = (void *)hxgep;

	mrf.mrf_normal_blank_time = RXDMA_RCR_TO_DEFAULT;
	mrf.mrf_normal_pkt_count = RXDMA_RCR_PTHRES_DEFAULT;

	rcr_rings = hxgep->rx_rcr_rings;
	rcr_p = rcr_rings->rcr_rings;
	ndmas = rcr_rings->ndmas;

	/*
	 * Export our receive resources to the MAC layer.
	 */
	for (i = 0; i < ndmas; i++) {
		rcrp = (void *)(p_rx_rcr_ring_t)rcr_p[i];
		rcrp->rcr_mac_handle =
		    mac_resource_add(hxgep->mach, (mac_resource_t *)&mrf);

		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "==> hxge_m_resources: vdma %d dma %d "
		    "rcrptr 0x%016llx mac_handle 0x%016llx",
		    i, rcrp->rdc, rcr_p[i], rcrp->rcr_mac_handle));
	}

	MUTEX_EXIT(hxgep->genlock);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_m_resources"));
}

/*
 * Set an alternate MAC address
 */
static int
hxge_altmac_set(p_hxge_t hxgep, uint8_t *maddr, mac_addr_slot_t slot)
{
	uint64_t	address;
	uint64_t	tmp;
	hpi_status_t	status;
	uint8_t		addrn;
	int		i;

	/*
	 * Convert a byte array to a 48 bit value.
	 * Need to check endianess if in doubt
	 */
	address = 0;
	for (i = 0; i < ETHERADDRL; i++) {
		tmp = maddr[i];
		address <<= 8;
		address |= tmp;
	}

	addrn = (uint8_t)slot;
	status = hpi_pfc_set_mac_address(hxgep->hpi_handle, addrn, address);
	if (status != HPI_SUCCESS)
		return (EIO);

	return (0);
}

static void
hxge_mmac_kstat_update(p_hxge_t hxgep, mac_addr_slot_t slot)
{
	p_hxge_mmac_stats_t	mmac_stats;
	int			i;
	hxge_mmac_t		*mmac_info;

	mmac_info = &hxgep->hxge_mmac_info;
	mmac_stats = &hxgep->statsp->mmac_stats;
	mmac_stats->mmac_max_cnt = mmac_info->num_mmac;
	mmac_stats->mmac_avail_cnt = mmac_info->naddrfree;

	for (i = 0; i < ETHERADDRL; i++) {
		mmac_stats->mmac_avail_pool[slot].ether_addr_octet[i] =
		    mmac_info->mac_pool[slot].addr[(ETHERADDRL - 1) - i];
	}
}

/*
 * Find an unused address slot, set the address value to the one specified,
 * enable the port to start filtering on the new MAC address.
 * Returns: 0 on success.
 */
int
hxge_m_mmac_add(void *arg, mac_multi_addr_t *maddr)
{
	p_hxge_t	hxgep = arg;
	mac_addr_slot_t	slot;
	hxge_mmac_t	*mmac_info;
	int		err;
	hxge_status_t	status;

	mutex_enter(hxgep->genlock);

	/*
	 * Make sure that hxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = hxge_init(hxgep);
		if (status != HXGE_OK) {
			mutex_exit(hxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &hxgep->hxge_mmac_info;
	if (mmac_info->naddrfree == 0) {
		mutex_exit(hxgep->genlock);
		return (ENOSPC);
	}

	if (!mac_unicst_verify(hxgep->mach, maddr->mma_addr,
	    maddr->mma_addrlen)) {
		mutex_exit(hxgep->genlock);
		return (EINVAL);
	}

	/*
	 * Search for the first available slot. Because naddrfree
	 * is not zero, we are guaranteed to find one.
	 * Slot 0 is for unique (primary) MAC.  The first alternate
	 * MAC slot is slot 1.
	 */
	for (slot = 1; slot < mmac_info->num_mmac; slot++) {
		if (!(mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED))
			break;
	}

	ASSERT(slot < mmac_info->num_mmac);
	if ((err = hxge_altmac_set(hxgep, maddr->mma_addr, slot)) != 0) {
		mutex_exit(hxgep->genlock);
		return (err);
	}
	bcopy(maddr->mma_addr, mmac_info->mac_pool[slot].addr, ETHERADDRL);
	mmac_info->mac_pool[slot].flags |= MMAC_SLOT_USED;
	mmac_info->naddrfree--;
	hxge_mmac_kstat_update(hxgep, slot);

	maddr->mma_slot = slot;

	mutex_exit(hxgep->genlock);
	return (0);
}

/*
 * Remove the specified mac address and update
 * the h/w not to filter the mac address anymore.
 * Returns: 0, on success.
 */
int
hxge_m_mmac_remove(void *arg, mac_addr_slot_t slot)
{
	p_hxge_t	hxgep = arg;
	hxge_mmac_t	*mmac_info;
	int		err = 0;
	hxge_status_t	status;

	mutex_enter(hxgep->genlock);

	/*
	 * Make sure that hxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = hxge_init(hxgep);
		if (status != HXGE_OK) {
			mutex_exit(hxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &hxgep->hxge_mmac_info;
	if (slot <= 0 || slot >= mmac_info->num_mmac) {
		mutex_exit(hxgep->genlock);
		return (EINVAL);
	}

	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED) {
		if (hpi_pfc_mac_addr_disable(hxgep->hpi_handle, slot) ==
		    HPI_SUCCESS) {
			mmac_info->mac_pool[slot].flags &= ~MMAC_SLOT_USED;
			mmac_info->naddrfree++;
			/*
			 * Clear mac_pool[slot].addr so that kstat shows 0
			 * alternate MAC address if the slot is not used.
			 */
			bzero(mmac_info->mac_pool[slot].addr, ETHERADDRL);
			hxge_mmac_kstat_update(hxgep, slot);
		} else {
			err = EIO;
		}
	} else {
		err = EINVAL;
	}

	mutex_exit(hxgep->genlock);
	return (err);
}

/*
 * Modify a mac address added by hxge_mmac_add().
 * Returns: 0, on success.
 */
int
hxge_m_mmac_modify(void *arg, mac_multi_addr_t *maddr)
{
	p_hxge_t	hxgep = arg;
	mac_addr_slot_t	slot;
	hxge_mmac_t	*mmac_info;
	int		err = 0;
	hxge_status_t	status;

	if (!mac_unicst_verify(hxgep->mach, maddr->mma_addr,
	    maddr->mma_addrlen))
		return (EINVAL);

	slot = maddr->mma_slot;

	mutex_enter(hxgep->genlock);

	/*
	 * Make sure that hxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = hxge_init(hxgep);
		if (status != HXGE_OK) {
			mutex_exit(hxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &hxgep->hxge_mmac_info;
	if (slot <= 0 || slot >= mmac_info->num_mmac) {
		mutex_exit(hxgep->genlock);
		return (EINVAL);
	}

	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED) {
		if ((err = hxge_altmac_set(hxgep, maddr->mma_addr,
		    slot)) == 0) {
			bcopy(maddr->mma_addr, mmac_info->mac_pool[slot].addr,
			    ETHERADDRL);
			hxge_mmac_kstat_update(hxgep, slot);
		}
	} else {
		err = EINVAL;
	}

	mutex_exit(hxgep->genlock);
	return (err);
}

/*
 * static int
 * hxge_m_mmac_get() - Get the MAC address and other information
 *	related to the slot.  mma_flags should be set to 0 in the call.
 *	Note: although kstat shows MAC address as zero when a slot is
 *	not used, Crossbow expects hxge_m_mmac_get to copy factory MAC
 *	to the caller as long as the slot is not using a user MAC address.
 *	The following table shows the rules,
 *
 *     					USED    VENDOR    mma_addr
 *	------------------------------------------------------------
 *	(1) Slot uses a user MAC:	yes      no     user MAC
 *	(2) Slot uses a factory MAC:    yes      yes    factory MAC
 *	(3) Slot is not used but is
 *	     factory MAC capable:	no       yes    factory MAC
 *	(4) Slot is not used and is
 *	     not factory MAC capable:   no       no	0
 *	------------------------------------------------------------
 */
int
hxge_m_mmac_get(void *arg, mac_multi_addr_t *maddr)
{
	hxge_t		*hxgep = arg;
	mac_addr_slot_t	slot;
	hxge_mmac_t	*mmac_info;
	hxge_status_t	status;

	slot = maddr->mma_slot;

	mutex_enter(hxgep->genlock);

	/*
	 * Make sure that hxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = hxge_init(hxgep);
		if (status != HXGE_OK) {
			mutex_exit(hxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &hxgep->hxge_mmac_info;
	if (slot <= 0 || slot >= mmac_info->num_mmac) {
		mutex_exit(hxgep->genlock);
		return (EINVAL);
	}

	maddr->mma_flags = 0;
	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED) {
		maddr->mma_flags |= MMAC_SLOT_USED;
		bcopy(mmac_info->mac_pool[slot].addr,
		    maddr->mma_addr, ETHERADDRL);
		maddr->mma_addrlen = ETHERADDRL;
	}

	mutex_exit(hxgep->genlock);
	return (0);
}

/*ARGSUSED*/
boolean_t
hxge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	p_hxge_t		hxgep = (p_hxge_t)arg;
	uint32_t		*txflags = cap_data;
	multiaddress_capab_t	*mmacp = cap_data;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		*txflags = HCKSUM_INET_PARTIAL;
		break;

	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, simply returning B_TRUE
		 * stating that we support polling is sufficient.
		 */
		break;

	case MAC_CAPAB_MULTIADDRESS:
		/*
		 * The number of MAC addresses made available by
		 * this capability is one less than the total as
		 * the primary address in slot 0 is counted in
		 * the total.
		 */
		mmacp->maddr_naddr = PFC_N_MAC_ADDRESSES - 1;
		mmacp->maddr_naddrfree = hxgep->hxge_mmac_info.naddrfree;
		mmacp->maddr_flag = 0;	/* No multiple factory macs */
		mmacp->maddr_handle = hxgep;
		mmacp->maddr_add = hxge_m_mmac_add;
		mmacp->maddr_remove = hxge_m_mmac_remove;
		mmacp->maddr_modify = hxge_m_mmac_modify;
		mmacp->maddr_get = hxge_m_mmac_get;
		mmacp->maddr_reserve = NULL;	/* No multiple factory macs */
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
hxge_param_locked(mac_prop_id_t pr_num)
{
	/*
	 * All adv_* parameters are locked (read-only) while
	 * the device is in any sort of loopback mode ...
	 */
	switch (pr_num) {
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:
		case MAC_PROP_AUTONEG:
		case MAC_PROP_FLOWCTRL:
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * callback functions for set/get of properties
 */
static int
hxge_m_setprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	hxge_t		*hxgep = barg;
	p_hxge_stats_t	statsp;
	int		err = 0;
	uint32_t	new_mtu, old_framesize, new_framesize;

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL, "==> hxge_m_setprop"));

	statsp = hxgep->statsp;
	mutex_enter(hxgep->genlock);
	if (statsp->port_stats.lb_mode != hxge_lb_normal &&
	    hxge_param_locked(pr_num)) {
		/*
		 * All adv_* parameters are locked (read-only)
		 * while the device is in any sort of loopback mode.
		 */
		HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
		    "==> hxge_m_setprop: loopback mode: read only"));
		mutex_exit(hxgep->genlock);
		return (EBUSY);
	}

	switch (pr_num) {
		/*
		 * These properties are either not exist or read only
		 */
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_STATUS:
		case MAC_PROP_SPEED:
		case MAC_PROP_DUPLEX:
		case MAC_PROP_AUTONEG:
		/*
		 * Flow control is handled in the shared domain and
		 * it is readonly here.
		 */
		case MAC_PROP_FLOWCTRL:
			err = EINVAL;
			HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
			    "==> hxge_m_setprop:  read only property %d",
			    pr_num));
			break;

		case MAC_PROP_MTU:
			if (hxgep->hxge_mac_state == HXGE_MAC_STARTED) {
				err = EBUSY;
				break;
			}

			bcopy(pr_val, &new_mtu, sizeof (new_mtu));
			HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
			    "==> hxge_m_setprop: set MTU: %d", new_mtu));

			new_framesize = new_mtu + MTU_TO_FRAME_SIZE;
			if (new_framesize == hxgep->vmac.maxframesize) {
				err = 0;
				break;
			}

			if (new_framesize < MIN_FRAME_SIZE ||
			    new_framesize > MAX_FRAME_SIZE) {
				err = EINVAL;
				break;
			}

			old_framesize = hxgep->vmac.maxframesize;
			hxgep->vmac.maxframesize = (uint16_t)new_framesize;

			if (hxge_vmac_set_framesize(hxgep)) {
				hxgep->vmac.maxframesize =
				    (uint16_t)old_framesize;
				err = EINVAL;
				break;
			}

			err = mac_maxsdu_update(hxgep->mach, new_mtu);
			if (err) {
				hxgep->vmac.maxframesize =
				    (uint16_t)old_framesize;
				(void) hxge_vmac_set_framesize(hxgep);
			}

			HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
			    "==> hxge_m_setprop: set MTU: %d maxframe %d",
			    new_mtu, hxgep->vmac.maxframesize));
			break;

		case MAC_PROP_PRIVATE:
			HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
			    "==> hxge_m_setprop: private property"));
			err = hxge_set_priv_prop(hxgep, pr_name, pr_valsize,
			    pr_val);
			break;

		default:
			err = ENOTSUP;
			break;
	}

	mutex_exit(hxgep->genlock);

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
	    "<== hxge_m_setprop (return %d)", err));

	return (err);
}

/* ARGSUSED */
static int
hxge_get_def_val(hxge_t *hxgep, mac_prop_id_t pr_num, uint_t pr_valsize,
    void *pr_val)
{
	int		err = 0;
	link_flowctrl_t	fl;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		*(uint8_t *)pr_val = 2;
		break;
	case MAC_PROP_AUTONEG:
		*(uint8_t *)pr_val = 0;
		break;
	case MAC_PROP_FLOWCTRL:
		if (pr_valsize < sizeof (link_flowctrl_t))
			return (EINVAL);
		fl = LINK_FLOWCTRL_TX;
		bcopy(&fl, pr_val, sizeof (fl));
		break;
	default:
		err = ENOTSUP;
		break;
	}
	return (err);
}

static int
hxge_m_getprop(void *barg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_flags, uint_t pr_valsize, void *pr_val)
{
	hxge_t 		*hxgep = barg;
	p_hxge_stats_t	statsp = hxgep->statsp;
	int		err = 0;
	link_flowctrl_t fl;
	uint64_t	tmp = 0;
	link_state_t	ls;

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
	    "==> hxge_m_getprop: pr_num %d", pr_num));

	if (pr_valsize == 0)
		return (EINVAL);

	if ((pr_flags & MAC_PROP_DEFAULT) && (pr_num != MAC_PROP_PRIVATE)) {
		err = hxge_get_def_val(hxgep, pr_num, pr_valsize, pr_val);
		return (err);
	}

	bzero(pr_val, pr_valsize);
	switch (pr_num) {
		case MAC_PROP_DUPLEX:
			*(uint8_t *)pr_val = statsp->mac_stats.link_duplex;
			HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
			    "==> hxge_m_getprop: duplex mode %d",
			    *(uint8_t *)pr_val));
			break;

		case MAC_PROP_SPEED:
			if (pr_valsize < sizeof (uint64_t))
				return (EINVAL);
			tmp = statsp->mac_stats.link_speed * 1000000ull;
			bcopy(&tmp, pr_val, sizeof (tmp));
			break;

		case MAC_PROP_STATUS:
			if (pr_valsize < sizeof (link_state_t))
				return (EINVAL);
			if (!statsp->mac_stats.link_up)
				ls = LINK_STATE_DOWN;
			else
				ls = LINK_STATE_UP;
			bcopy(&ls, pr_val, sizeof (ls));
			break;

		case MAC_PROP_FLOWCTRL:
			/*
			 * Flow control is supported by the shared domain and
			 * it is currently transmit only
			 */
			if (pr_valsize < sizeof (link_flowctrl_t))
				return (EINVAL);
			fl = LINK_FLOWCTRL_TX;
			bcopy(&fl, pr_val, sizeof (fl));
			break;
		case MAC_PROP_AUTONEG:
			/* 10G link only and it is not negotiable */
			*(uint8_t *)pr_val = 0;
			break;
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:
			err = ENOTSUP;
			break;

		case MAC_PROP_PRIVATE:
			err = hxge_get_priv_prop(hxgep, pr_name, pr_flags,
			    pr_valsize, pr_val);
			break;
		default:
			err = EINVAL;
			break;
	}

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL, "<== hxge_m_getprop"));

	return (err);
}

/* ARGSUSED */
static int
hxge_set_priv_prop(p_hxge_t hxgep, const char *pr_name, uint_t pr_valsize,
    const void *pr_val)
{
	p_hxge_param_t	param_arr = hxgep->param_arr;
	int		err = 0;

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
	    "==> hxge_set_priv_prop: name %s (value %s)", pr_name, pr_val));

	if (pr_val == NULL) {
		return (EINVAL);
	}

	/* Blanking */
	if (strcmp(pr_name, "_rxdma_intr_time") == 0) {
		err = hxge_param_rx_intr_time(hxgep, NULL, NULL,
		    (char *)pr_val, (caddr_t)&param_arr[param_rxdma_intr_time]);
	} else if (strcmp(pr_name, "_rxdma_intr_pkts") == 0) {
		err = hxge_param_rx_intr_pkts(hxgep, NULL, NULL,
		    (char *)pr_val, (caddr_t)&param_arr[param_rxdma_intr_pkts]);

	/* Classification */
	} else if (strcmp(pr_name, "_class_opt_ipv4_tcp") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv4_tcp]);
	} else if (strcmp(pr_name, "_class_opt_ipv4_udp") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv4_udp]);
	} else if (strcmp(pr_name, "_class_opt_ipv4_ah") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv4_ah]);
	} else if (strcmp(pr_name, "_class_opt_ipv4_sctp") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv4_sctp]);
	} else if (strcmp(pr_name, "_class_opt_ipv6_tcp") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv6_tcp]);
	} else if (strcmp(pr_name, "_class_opt_ipv6_udp") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv6_udp]);
	} else if (strcmp(pr_name, "_class_opt_ipv6_ah") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv6_ah]);
	} else if (strcmp(pr_name, "_class_opt_ipv6_sctp") == 0) {
		err = hxge_param_set_ip_opt(hxgep, NULL, NULL, (char *)pr_val,
		    (caddr_t)&param_arr[param_class_opt_ipv6_sctp]);
	} else {
		err = EINVAL;
	}

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
	    "<== hxge_set_priv_prop: err %d", err));

	return (err);
}

static int
hxge_get_priv_prop(p_hxge_t hxgep, const char *pr_name, uint_t pr_flags,
    uint_t pr_valsize, void *pr_val)
{
	p_hxge_param_t	param_arr = hxgep->param_arr;
	char		valstr[MAXNAMELEN];
	int		err = 0;
	uint_t		strsize;
	int		value = 0;

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
	    "==> hxge_get_priv_prop: property %s", pr_name));

	if (pr_flags & MAC_PROP_DEFAULT) {
		/* Receive Interrupt Blanking Parameters */
		if (strcmp(pr_name, "_rxdma_intr_time") == 0) {
			value = RXDMA_RCR_TO_DEFAULT;
		} else if (strcmp(pr_name, "_rxdma_intr_pkts") == 0) {
			value = RXDMA_RCR_PTHRES_DEFAULT;

		/* Classification and Load Distribution Configuration */
		} else if (strcmp(pr_name, "_class_opt_ipv4_tcp") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv4_udp") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv4_ah") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv4_sctp") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv6_tcp") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv6_udp") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv6_ah") == 0 ||
		    strcmp(pr_name, "_class_opt_ipv6_sctp") == 0) {
			value = HXGE_CLASS_TCAM_LOOKUP;
		} else {
			err = EINVAL;
		}
	} else {
		/* Receive Interrupt Blanking Parameters */
		if (strcmp(pr_name, "_rxdma_intr_time") == 0) {
			value = hxgep->intr_timeout;
		} else if (strcmp(pr_name, "_rxdma_intr_pkts") == 0) {
			value = hxgep->intr_threshold;

		/* Classification and Load Distribution Configuration */
		} else if (strcmp(pr_name, "_class_opt_ipv4_tcp") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv4_tcp]);

			value = (int)param_arr[param_class_opt_ipv4_tcp].value;
		} else if (strcmp(pr_name, "_class_opt_ipv4_udp") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv4_udp]);

			value = (int)param_arr[param_class_opt_ipv4_udp].value;
		} else if (strcmp(pr_name, "_class_opt_ipv4_ah") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv4_ah]);

			value = (int)param_arr[param_class_opt_ipv4_ah].value;
		} else if (strcmp(pr_name, "_class_opt_ipv4_sctp") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv4_sctp]);

			value = (int)param_arr[param_class_opt_ipv4_sctp].value;
		} else if (strcmp(pr_name, "_class_opt_ipv6_tcp") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv6_tcp]);

			value = (int)param_arr[param_class_opt_ipv6_tcp].value;
		} else if (strcmp(pr_name, "_class_opt_ipv6_udp") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv6_udp]);

			value = (int)param_arr[param_class_opt_ipv6_udp].value;
		} else if (strcmp(pr_name, "_class_opt_ipv6_ah") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv6_ah]);

			value = (int)param_arr[param_class_opt_ipv6_ah].value;
		} else if (strcmp(pr_name, "_class_opt_ipv6_sctp") == 0) {
			err = hxge_param_get_ip_opt(hxgep, NULL, NULL,
			    (caddr_t)&param_arr[param_class_opt_ipv6_sctp]);

			value = (int)param_arr[param_class_opt_ipv6_sctp].value;
		} else {
			err = EINVAL;
		}
	}

	if (err == 0) {
		(void) snprintf(valstr, sizeof (valstr), "0x%x", value);

		strsize = (uint_t)strlen(valstr);
		if (pr_valsize < strsize) {
			err = ENOBUFS;
		} else {
			(void) strlcpy(pr_val, valstr, pr_valsize);
		}
	}

	HXGE_DEBUG_MSG((hxgep, DLADM_CTL,
	    "<== hxge_get_priv_prop: return %d", err));

	return (err);
}
/*
 * Module loading and removing entry points.
 */
DDI_DEFINE_STREAM_OPS(hxge_dev_ops, nulldev, nulldev, hxge_attach, hxge_detach,
    nodev, NULL, D_MP, NULL, NULL);

extern struct mod_ops mod_driverops;

#define	HXGE_DESC_VER	"HXGE 10Gb Ethernet Driver"

/*
 * Module linkage information for the kernel.
 */
static struct modldrv hxge_modldrv = {
	&mod_driverops,
	HXGE_DESC_VER,
	&hxge_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &hxge_modldrv, NULL
};

int
_init(void)
{
	int status;

	HXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _init"));
	mac_init_ops(&hxge_dev_ops, "hxge");
	status = ddi_soft_state_init(&hxge_list, sizeof (hxge_t), 0);
	if (status != 0) {
		HXGE_ERROR_MSG((NULL, HXGE_ERR_CTL,
		    "failed to init device soft state"));
		mac_fini_ops(&hxge_dev_ops);
		goto _init_exit;
	}

	status = mod_install(&modlinkage);
	if (status != 0) {
		ddi_soft_state_fini(&hxge_list);
		HXGE_ERROR_MSG((NULL, HXGE_ERR_CTL, "Mod install failed"));
		goto _init_exit;
	}

	MUTEX_INIT(&hxge_common_lock, NULL, MUTEX_DRIVER, NULL);

_init_exit:
	HXGE_DEBUG_MSG((NULL, MOD_CTL, "_init status = 0x%X", status));

	return (status);
}

int
_fini(void)
{
	int status;

	HXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _fini"));

	HXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _fini: mod_remove"));

	if (hxge_mblks_pending)
		return (EBUSY);

	status = mod_remove(&modlinkage);
	if (status != DDI_SUCCESS) {
		HXGE_DEBUG_MSG((NULL, MOD_CTL,
		    "Module removal failed 0x%08x", status));
		goto _fini_exit;
	}

	mac_fini_ops(&hxge_dev_ops);

	ddi_soft_state_fini(&hxge_list);

	MUTEX_DESTROY(&hxge_common_lock);

_fini_exit:
	HXGE_DEBUG_MSG((NULL, MOD_CTL, "_fini status = 0x%08x", status));

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	int status;

	HXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _info"));
	status = mod_info(&modlinkage, modinfop);
	HXGE_DEBUG_MSG((NULL, MOD_CTL, " _info status = 0x%X", status));

	return (status);
}

/*ARGSUSED*/
hxge_status_t
hxge_add_intrs(p_hxge_t hxgep)
{
	int		intr_types;
	int		type = 0;
	int		ddi_status = DDI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs"));

	hxgep->hxge_intr_type.intr_registered = B_FALSE;
	hxgep->hxge_intr_type.intr_enabled = B_FALSE;
	hxgep->hxge_intr_type.msi_intx_cnt = 0;
	hxgep->hxge_intr_type.intr_added = 0;
	hxgep->hxge_intr_type.niu_msi_enable = B_FALSE;
	hxgep->hxge_intr_type.intr_type = 0;

	if (hxge_msi_enable) {
		hxgep->hxge_intr_type.niu_msi_enable = B_TRUE;
	}

	/* Get the supported interrupt types */
	if ((ddi_status = ddi_intr_get_supported_types(hxgep->dip, &intr_types))
	    != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "<== hxge_add_intrs: "
		    "ddi_intr_get_supported_types failed: status 0x%08x",
		    ddi_status));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	hxgep->hxge_intr_type.intr_types = intr_types;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs: "
	    "ddi_intr_get_supported_types: 0x%08x", intr_types));

	/*
	 * Pick the interrupt type to use MSIX, MSI, INTX hxge_msi_enable:
	 *	(1): 1 - MSI
	 *	(2): 2 - MSI-X
	 *	others - FIXED
	 */
	switch (hxge_msi_enable) {
	default:
		type = DDI_INTR_TYPE_FIXED;
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs: "
		    "use fixed (intx emulation) type %08x", type));
		break;

	case 2:
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs: "
		    "ddi_intr_get_supported_types: 0x%08x", intr_types));
		if (intr_types & DDI_INTR_TYPE_MSIX) {
			type = DDI_INTR_TYPE_MSIX;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_add_intrs: "
			    "ddi_intr_get_supported_types: MSIX 0x%08x", type));
		} else if (intr_types & DDI_INTR_TYPE_MSI) {
			type = DDI_INTR_TYPE_MSI;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_add_intrs: "
			    "ddi_intr_get_supported_types: MSI 0x%08x", type));
		} else if (intr_types & DDI_INTR_TYPE_FIXED) {
			type = DDI_INTR_TYPE_FIXED;
			HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs: "
			    "ddi_intr_get_supported_types: MSXED0x%08x", type));
		}
		break;

	case 1:
		if (intr_types & DDI_INTR_TYPE_MSI) {
			type = DDI_INTR_TYPE_MSI;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_add_intrs: "
			    "ddi_intr_get_supported_types: MSI 0x%08x", type));
		} else if (intr_types & DDI_INTR_TYPE_MSIX) {
			type = DDI_INTR_TYPE_MSIX;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_add_intrs: "
			    "ddi_intr_get_supported_types: MSIX 0x%08x", type));
		} else if (intr_types & DDI_INTR_TYPE_FIXED) {
			type = DDI_INTR_TYPE_FIXED;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_add_intrs: "
			    "ddi_intr_get_supported_types: MSXED0x%08x", type));
		}
	}

	hxgep->hxge_intr_type.intr_type = type;
	if ((type == DDI_INTR_TYPE_MSIX || type == DDI_INTR_TYPE_MSI ||
	    type == DDI_INTR_TYPE_FIXED) &&
	    hxgep->hxge_intr_type.niu_msi_enable) {
		if ((status = hxge_add_intrs_adv(hxgep)) != DDI_SUCCESS) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    " hxge_add_intrs: "
			    " hxge_add_intrs_adv failed: status 0x%08x",
			    status));
			return (status);
		} else {
			HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_add_intrs: "
			    "interrupts registered : type %d", type));
			hxgep->hxge_intr_type.intr_registered = B_TRUE;

			HXGE_DEBUG_MSG((hxgep, DDI_CTL,
			    "\nAdded advanced hxge add_intr_adv "
			    "intr type 0x%x\n", type));

			return (status);
		}
	}

	if (!hxgep->hxge_intr_type.intr_registered) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_add_intrs: failed to register interrupts"));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_add_intrs"));

	return (status);
}

/*ARGSUSED*/
static hxge_status_t
hxge_add_soft_intrs(p_hxge_t hxgep)
{
	int		ddi_status = DDI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_add_soft_intrs"));

	hxgep->resched_id = NULL;
	hxgep->resched_running = B_FALSE;
	ddi_status = ddi_add_softintr(hxgep->dip, DDI_SOFTINT_LOW,
	    &hxgep->resched_id, NULL, NULL, hxge_reschedule, (caddr_t)hxgep);
	if (ddi_status != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "<== hxge_add_soft_intrs: "
		    "ddi_add_softintrs failed: status 0x%08x", ddi_status));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_ddi_add_soft_intrs"));

	return (status);
}

/*ARGSUSED*/
static hxge_status_t
hxge_add_intrs_adv(p_hxge_t hxgep)
{
	int		intr_type;
	p_hxge_intr_t	intrp;
	hxge_status_t	status;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs_adv"));

	intrp = (p_hxge_intr_t)&hxgep->hxge_intr_type;
	intr_type = intrp->intr_type;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs_adv: type 0x%x",
	    intr_type));

	switch (intr_type) {
	case DDI_INTR_TYPE_MSI:		/* 0x2 */
	case DDI_INTR_TYPE_MSIX:	/* 0x4 */
		status = hxge_add_intrs_adv_type(hxgep, intr_type);
		break;

	case DDI_INTR_TYPE_FIXED:	/* 0x1 */
		status = hxge_add_intrs_adv_type_fix(hxgep, intr_type);
		break;

	default:
		status = HXGE_ERROR;
		break;
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_add_intrs_adv"));

	return (status);
}

/*ARGSUSED*/
static hxge_status_t
hxge_add_intrs_adv_type(p_hxge_t hxgep, uint32_t int_type)
{
	dev_info_t	*dip = hxgep->dip;
	p_hxge_ldg_t	ldgp;
	p_hxge_intr_t	intrp;
	uint_t		*inthandler;
	void		*arg1, *arg2;
	int		behavior;
	int		nintrs, navail;
	int		nactual, nrequired;
	int		inum = 0;
	int		loop = 0;
	int		x, y;
	int		ddi_status = DDI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs_adv_type"));

	intrp = (p_hxge_intr_t)&hxgep->hxge_intr_type;

	ddi_status = ddi_intr_get_nintrs(dip, int_type, &nintrs);
	if ((ddi_status != DDI_SUCCESS) || (nintrs == 0)) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_intr_get_nintrs() failed, status: 0x%x%, "
		    "nintrs: %d", ddi_status, nintrs));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	ddi_status = ddi_intr_get_navail(dip, int_type, &navail);
	if ((ddi_status != DDI_SUCCESS) || (navail == 0)) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_intr_get_navail() failed, status: 0x%x%, "
		    "nintrs: %d", ddi_status, navail));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "ddi_intr_get_navail() returned: intr type %d nintrs %d, navail %d",
	    int_type, nintrs, navail));

	if (int_type == DDI_INTR_TYPE_MSI && !ISP2(navail)) {
		/* MSI must be power of 2 */
		if ((navail & 16) == 16) {
			navail = 16;
		} else if ((navail & 8) == 8) {
			navail = 8;
		} else if ((navail & 4) == 4) {
			navail = 4;
		} else if ((navail & 2) == 2) {
			navail = 2;
		} else {
			navail = 1;
		}
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "ddi_intr_get_navail(): (msi power of 2) nintrs %d, "
		    "navail %d", nintrs, navail));
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "requesting: intr type %d nintrs %d, navail %d",
	    int_type, nintrs, navail));

	behavior = ((int_type == DDI_INTR_TYPE_FIXED) ? DDI_INTR_ALLOC_STRICT :
	    DDI_INTR_ALLOC_NORMAL);
	intrp->intr_size = navail * sizeof (ddi_intr_handle_t);
	intrp->htable = kmem_zalloc(intrp->intr_size, KM_SLEEP);

	ddi_status = ddi_intr_alloc(dip, intrp->htable, int_type, inum,
	    navail, &nactual, behavior);
	if (ddi_status != DDI_SUCCESS || nactual == 0) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " ddi_intr_alloc() failed: %d", ddi_status));
		kmem_free(intrp->htable, intrp->intr_size);
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "ddi_intr_alloc() returned: navail %d nactual %d",
	    navail, nactual));

	if ((ddi_status = ddi_intr_get_pri(intrp->htable[0],
	    (uint_t *)&intrp->pri)) != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " ddi_intr_get_pri() failed: %d", ddi_status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	nrequired = 0;
	status = hxge_ldgv_init(hxgep, &nactual, &nrequired);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_add_intrs_adv_typ:hxge_ldgv_init "
		    "failed: 0x%x", status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (status);
	}

	ldgp = hxgep->ldgvp->ldgp;
	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "After hxge_ldgv_init(): nreq %d nactual %d", nrequired, nactual));

	if (nactual < nrequired)
		loop = nactual;
	else
		loop = nrequired;

	for (x = 0; x < loop; x++, ldgp++) {
		ldgp->vector = (uint8_t)x;
		arg1 = ldgp->ldvp;
		arg2 = hxgep;
		if (ldgp->nldvs == 1) {
			inthandler = (uint_t *)ldgp->ldvp->ldv_intr_handler;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "hxge_add_intrs_adv_type: arg1 0x%x arg2 0x%x: "
			    "1-1 int handler (entry %d)\n",
			    arg1, arg2, x));
		} else if (ldgp->nldvs > 1) {
			inthandler = (uint_t *)ldgp->sys_intr_handler;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "hxge_add_intrs_adv_type: arg1 0x%x arg2 0x%x: "
			    "nldevs %d int handler (entry %d)\n",
			    arg1, arg2, ldgp->nldvs, x));
		}
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_add_intrs_adv_type: ddi_add_intr(inum) #%d "
		    "htable 0x%llx", x, intrp->htable[x]));

		if ((ddi_status = ddi_intr_add_handler(intrp->htable[x],
		    (ddi_intr_handler_t *)inthandler, arg1, arg2)) !=
		    DDI_SUCCESS) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_add_intrs_adv_type: failed #%d "
			    "status 0x%x", x, ddi_status));
			for (y = 0; y < intrp->intr_added; y++) {
				(void) ddi_intr_remove_handler(
				    intrp->htable[y]);
			}

			/* Free already allocated intr */
			for (y = 0; y < nactual; y++) {
				(void) ddi_intr_free(intrp->htable[y]);
			}
			kmem_free(intrp->htable, intrp->intr_size);

			(void) hxge_ldgv_uninit(hxgep);

			return (HXGE_ERROR | HXGE_DDI_FAILED);
		}

		intrp->intr_added++;
	}
	intrp->msi_intx_cnt = nactual;

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "Requested: %d, Allowed: %d msi_intx_cnt %d intr_added %d",
	    navail, nactual, intrp->msi_intx_cnt, intrp->intr_added));

	(void) ddi_intr_get_cap(intrp->htable[0], &intrp->intr_cap);
	(void) hxge_intr_ldgv_init(hxgep);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_add_intrs_adv_type"));

	return (status);
}

/*ARGSUSED*/
static hxge_status_t
hxge_add_intrs_adv_type_fix(p_hxge_t hxgep, uint32_t int_type)
{
	dev_info_t	*dip = hxgep->dip;
	p_hxge_ldg_t	ldgp;
	p_hxge_intr_t	intrp;
	uint_t		*inthandler;
	void		*arg1, *arg2;
	int		behavior;
	int		nintrs, navail;
	int		nactual, nrequired;
	int		inum = 0;
	int		x, y;
	int		ddi_status = DDI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_add_intrs_adv_type_fix"));
	intrp = (p_hxge_intr_t)&hxgep->hxge_intr_type;

	ddi_status = ddi_intr_get_nintrs(dip, int_type, &nintrs);
	if ((ddi_status != DDI_SUCCESS) || (nintrs == 0)) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "ddi_intr_get_nintrs() failed, status: 0x%x%, "
		    "nintrs: %d", status, nintrs));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	ddi_status = ddi_intr_get_navail(dip, int_type, &navail);
	if ((ddi_status != DDI_SUCCESS) || (navail == 0)) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "ddi_intr_get_navail() failed, status: 0x%x%, "
		    "nintrs: %d", ddi_status, navail));
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "ddi_intr_get_navail() returned: nintrs %d, naavail %d",
	    nintrs, navail));

	behavior = ((int_type == DDI_INTR_TYPE_FIXED) ? DDI_INTR_ALLOC_STRICT :
	    DDI_INTR_ALLOC_NORMAL);
	intrp->intr_size = navail * sizeof (ddi_intr_handle_t);
	intrp->htable = kmem_alloc(intrp->intr_size, KM_SLEEP);
	ddi_status = ddi_intr_alloc(dip, intrp->htable, int_type, inum,
	    navail, &nactual, behavior);
	if (ddi_status != DDI_SUCCESS || nactual == 0) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " ddi_intr_alloc() failed: %d", ddi_status));
		kmem_free(intrp->htable, intrp->intr_size);
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	if ((ddi_status = ddi_intr_get_pri(intrp->htable[0],
	    (uint_t *)&intrp->pri)) != DDI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " ddi_intr_get_pri() failed: %d", ddi_status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (HXGE_ERROR | HXGE_DDI_FAILED);
	}

	nrequired = 0;
	status = hxge_ldgv_init(hxgep, &nactual, &nrequired);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_add_intrs_adv_type_fix:hxge_ldgv_init "
		    "failed: 0x%x", status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (status);
	}

	ldgp = hxgep->ldgvp->ldgp;
	for (x = 0; x < nrequired; x++, ldgp++) {
		ldgp->vector = (uint8_t)x;
		arg1 = ldgp->ldvp;
		arg2 = hxgep;
		if (ldgp->nldvs == 1) {
			inthandler = (uint_t *)ldgp->ldvp->ldv_intr_handler;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "hxge_add_intrs_adv_type_fix: "
			    "1-1 int handler(%d) ldg %d ldv %d "
			    "arg1 $%p arg2 $%p\n",
			    x, ldgp->ldg, ldgp->ldvp->ldv, arg1, arg2));
		} else if (ldgp->nldvs > 1) {
			inthandler = (uint_t *)ldgp->sys_intr_handler;
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "hxge_add_intrs_adv_type_fix: "
			    "shared ldv %d int handler(%d) ldv %d ldg %d"
			    "arg1 0x%016llx arg2 0x%016llx\n",
			    x, ldgp->nldvs, ldgp->ldg, ldgp->ldvp->ldv,
			    arg1, arg2));
		}

		if ((ddi_status = ddi_intr_add_handler(intrp->htable[x],
		    (ddi_intr_handler_t *)inthandler, arg1, arg2)) !=
		    DDI_SUCCESS) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_add_intrs_adv_type_fix: failed #%d "
			    "status 0x%x", x, ddi_status));
			for (y = 0; y < intrp->intr_added; y++) {
				(void) ddi_intr_remove_handler(
				    intrp->htable[y]);
			}
			for (y = 0; y < nactual; y++) {
				(void) ddi_intr_free(intrp->htable[y]);
			}
			/* Free already allocated intr */
			kmem_free(intrp->htable, intrp->intr_size);

			(void) hxge_ldgv_uninit(hxgep);

			return (HXGE_ERROR | HXGE_DDI_FAILED);
		}
		intrp->intr_added++;
	}

	intrp->msi_intx_cnt = nactual;

	(void) ddi_intr_get_cap(intrp->htable[0], &intrp->intr_cap);

	status = hxge_intr_ldgv_init(hxgep);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_add_intrs_adv_type_fix"));

	return (status);
}

/*ARGSUSED*/
static void
hxge_remove_intrs(p_hxge_t hxgep)
{
	int		i, inum;
	p_hxge_intr_t	intrp;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_remove_intrs"));
	intrp = (p_hxge_intr_t)&hxgep->hxge_intr_type;
	if (!intrp->intr_registered) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "<== hxge_remove_intrs: interrupts not registered"));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_remove_intrs:advanced"));

	if (intrp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(intrp->htable,
		    intrp->intr_added);
	} else {
		for (i = 0; i < intrp->intr_added; i++) {
			(void) ddi_intr_disable(intrp->htable[i]);
		}
	}

	for (inum = 0; inum < intrp->intr_added; inum++) {
		if (intrp->htable[inum]) {
			(void) ddi_intr_remove_handler(intrp->htable[inum]);
		}
	}

	for (inum = 0; inum < intrp->msi_intx_cnt; inum++) {
		if (intrp->htable[inum]) {
			HXGE_DEBUG_MSG((hxgep, DDI_CTL,
			    "hxge_remove_intrs: ddi_intr_free inum %d "
			    "msi_intx_cnt %d intr_added %d",
			    inum, intrp->msi_intx_cnt, intrp->intr_added));

			(void) ddi_intr_free(intrp->htable[inum]);
		}
	}

	kmem_free(intrp->htable, intrp->intr_size);
	intrp->intr_registered = B_FALSE;
	intrp->intr_enabled = B_FALSE;
	intrp->msi_intx_cnt = 0;
	intrp->intr_added = 0;

	(void) hxge_ldgv_uninit(hxgep);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_remove_intrs"));
}

/*ARGSUSED*/
static void
hxge_remove_soft_intrs(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_remove_soft_intrs"));

	if (hxgep->resched_id) {
		ddi_remove_softintr(hxgep->resched_id);
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_remove_soft_intrs: removed"));
		hxgep->resched_id = NULL;
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_remove_soft_intrs"));
}

/*ARGSUSED*/
void
hxge_intrs_enable(p_hxge_t hxgep)
{
	p_hxge_intr_t	intrp;
	int		i;
	int		status;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intrs_enable"));

	intrp = (p_hxge_intr_t)&hxgep->hxge_intr_type;

	if (!intrp->intr_registered) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "<== hxge_intrs_enable: "
		    "interrupts are not registered"));
		return;
	}

	if (intrp->intr_enabled) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "<== hxge_intrs_enable: already enabled"));
		return;
	}

	if (intrp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		status = ddi_intr_block_enable(intrp->htable,
		    intrp->intr_added);
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intrs_enable "
		    "block enable - status 0x%x total inums #%d\n",
		    status, intrp->intr_added));
	} else {
		for (i = 0; i < intrp->intr_added; i++) {
			status = ddi_intr_enable(intrp->htable[i]);
			HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intrs_enable "
			    "ddi_intr_enable:enable - status 0x%x "
			    "total inums %d enable inum #%d\n",
			    status, intrp->intr_added, i));
			if (status == DDI_SUCCESS) {
				intrp->intr_enabled = B_TRUE;
			}
		}
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intrs_enable"));
}

/*ARGSUSED*/
static void
hxge_intrs_disable(p_hxge_t hxgep)
{
	p_hxge_intr_t	intrp;
	int		i;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intrs_disable"));

	intrp = (p_hxge_intr_t)&hxgep->hxge_intr_type;

	if (!intrp->intr_registered) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intrs_disable: "
		    "interrupts are not registered"));
		return;
	}

	if (intrp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(intrp->htable,
		    intrp->intr_added);
	} else {
		for (i = 0; i < intrp->intr_added; i++) {
			(void) ddi_intr_disable(intrp->htable[i]);
		}
	}

	intrp->intr_enabled = B_FALSE;
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intrs_disable"));
}

static hxge_status_t
hxge_mac_register(p_hxge_t hxgep)
{
	mac_register_t	*macp;
	int		status;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_mac_register"));

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		return (HXGE_ERROR);

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = hxgep;
	macp->m_dip = hxgep->dip;
	macp->m_src_addr = hxgep->ouraddr.ether_addr_octet;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL,
	    "hxge_mac_register: ether addr is %x:%x:%x:%x:%x:%x",
	    macp->m_src_addr[0],
	    macp->m_src_addr[1],
	    macp->m_src_addr[2],
	    macp->m_src_addr[3],
	    macp->m_src_addr[4],
	    macp->m_src_addr[5]));

	macp->m_callbacks = &hxge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = hxgep->vmac.maxframesize - MTU_TO_FRAME_SIZE;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = hxge_priv_props;
	macp->m_priv_prop_count = HXGE_MAX_PRIV_PROPS;

	status = mac_register(macp, &hxgep->mach);
	mac_free(macp);

	if (status != 0) {
		cmn_err(CE_WARN,
		    "hxge_mac_register failed (status %d instance %d)",
		    status, hxgep->instance);
		return (HXGE_ERROR);
	}

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_mac_register success "
	    "(instance %d)", hxgep->instance));

	return (HXGE_OK);
}

static int
hxge_init_common_dev(p_hxge_t hxgep)
{
	p_hxge_hw_list_t	hw_p;
	dev_info_t		*p_dip;

	HXGE_DEBUG_MSG((hxgep, MOD_CTL, "==> hxge_init_common_dev"));

	p_dip = hxgep->p_dip;
	MUTEX_ENTER(&hxge_common_lock);

	/*
	 * Loop through existing per Hydra hardware list.
	 */
	for (hw_p = hxge_hw_list; hw_p; hw_p = hw_p->next) {
		HXGE_DEBUG_MSG((hxgep, MOD_CTL,
		    "==> hxge_init_common_dev: hw_p $%p parent dip $%p",
		    hw_p, p_dip));
		if (hw_p->parent_devp == p_dip) {
			hxgep->hxge_hw_p = hw_p;
			hw_p->ndevs++;
			hw_p->hxge_p = hxgep;
			HXGE_DEBUG_MSG((hxgep, MOD_CTL,
			    "==> hxge_init_common_device: "
			    "hw_p $%p parent dip $%p ndevs %d (found)",
			    hw_p, p_dip, hw_p->ndevs));
			break;
		}
	}

	if (hw_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, MOD_CTL,
		    "==> hxge_init_common_dev: parent dip $%p (new)", p_dip));
		hw_p = kmem_zalloc(sizeof (hxge_hw_list_t), KM_SLEEP);
		hw_p->parent_devp = p_dip;
		hw_p->magic = HXGE_MAGIC;
		hxgep->hxge_hw_p = hw_p;
		hw_p->ndevs++;
		hw_p->hxge_p = hxgep;
		hw_p->next = hxge_hw_list;

		MUTEX_INIT(&hw_p->hxge_cfg_lock, NULL, MUTEX_DRIVER, NULL);
		MUTEX_INIT(&hw_p->hxge_tcam_lock, NULL, MUTEX_DRIVER, NULL);
		MUTEX_INIT(&hw_p->hxge_vlan_lock, NULL, MUTEX_DRIVER, NULL);

		hxge_hw_list = hw_p;
	}
	MUTEX_EXIT(&hxge_common_lock);
	HXGE_DEBUG_MSG((hxgep, MOD_CTL,
	    "==> hxge_init_common_dev (hxge_hw_list) $%p", hxge_hw_list));
	HXGE_DEBUG_MSG((hxgep, MOD_CTL, "<== hxge_init_common_dev"));

	return (HXGE_OK);
}

static void
hxge_uninit_common_dev(p_hxge_t hxgep)
{
	p_hxge_hw_list_t	hw_p, h_hw_p;
	dev_info_t		*p_dip;

	HXGE_DEBUG_MSG((hxgep, MOD_CTL, "==> hxge_uninit_common_dev"));
	if (hxgep->hxge_hw_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, MOD_CTL,
		    "<== hxge_uninit_common_dev (no common)"));
		return;
	}

	MUTEX_ENTER(&hxge_common_lock);
	h_hw_p = hxge_hw_list;
	for (hw_p = hxge_hw_list; hw_p; hw_p = hw_p->next) {
		p_dip = hw_p->parent_devp;
		if (hxgep->hxge_hw_p == hw_p && p_dip == hxgep->p_dip &&
		    hxgep->hxge_hw_p->magic == HXGE_MAGIC &&
		    hw_p->magic == HXGE_MAGIC) {
			HXGE_DEBUG_MSG((hxgep, MOD_CTL,
			    "==> hxge_uninit_common_dev: "
			    "hw_p $%p parent dip $%p ndevs %d (found)",
			    hw_p, p_dip, hw_p->ndevs));

			hxgep->hxge_hw_p = NULL;
			if (hw_p->ndevs) {
				hw_p->ndevs--;
			}
			hw_p->hxge_p = NULL;
			if (!hw_p->ndevs) {
				MUTEX_DESTROY(&hw_p->hxge_vlan_lock);
				MUTEX_DESTROY(&hw_p->hxge_tcam_lock);
				MUTEX_DESTROY(&hw_p->hxge_cfg_lock);
				HXGE_DEBUG_MSG((hxgep, MOD_CTL,
				    "==> hxge_uninit_common_dev: "
				    "hw_p $%p parent dip $%p ndevs %d (last)",
				    hw_p, p_dip, hw_p->ndevs));

				if (hw_p == hxge_hw_list) {
					HXGE_DEBUG_MSG((hxgep, MOD_CTL,
					    "==> hxge_uninit_common_dev:"
					    "remove head "
					    "hw_p $%p parent dip $%p "
					    "ndevs %d (head)",
					    hw_p, p_dip, hw_p->ndevs));
					hxge_hw_list = hw_p->next;
				} else {
					HXGE_DEBUG_MSG((hxgep, MOD_CTL,
					    "==> hxge_uninit_common_dev:"
					    "remove middle "
					    "hw_p $%p parent dip $%p "
					    "ndevs %d (middle)",
					    hw_p, p_dip, hw_p->ndevs));
					h_hw_p->next = hw_p->next;
				}

				KMEM_FREE(hw_p, sizeof (hxge_hw_list_t));
			}
			break;
		} else {
			h_hw_p = hw_p;
		}
	}

	MUTEX_EXIT(&hxge_common_lock);
	HXGE_DEBUG_MSG((hxgep, MOD_CTL,
	    "==> hxge_uninit_common_dev (hxge_hw_list) $%p", hxge_hw_list));

	HXGE_DEBUG_MSG((hxgep, MOD_CTL, "<= hxge_uninit_common_dev"));
}

static void
hxge_link_poll(void *arg)
{
	p_hxge_t		hxgep = (p_hxge_t)arg;
	hpi_handle_t		handle;
	cip_link_stat_t		link_stat;
	hxge_timeout		*to = &hxgep->timeout;

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	HXGE_REG_RD32(handle, CIP_LINK_STAT, &link_stat.value);

	if (to->report_link_status ||
	    (to->link_status != link_stat.bits.xpcs0_link_up)) {
		to->link_status = link_stat.bits.xpcs0_link_up;
		to->report_link_status = B_FALSE;

		if (link_stat.bits.xpcs0_link_up) {
			hxge_link_update(hxgep, LINK_STATE_UP);
		} else {
			hxge_link_update(hxgep, LINK_STATE_DOWN);
		}
	}

	/* Restart the link status timer to check the link status */
	MUTEX_ENTER(&to->lock);
	to->id = timeout(hxge_link_poll, arg, to->ticks);
	MUTEX_EXIT(&to->lock);
}

static void
hxge_link_update(p_hxge_t hxgep, link_state_t state)
{
	p_hxge_stats_t		statsp = (p_hxge_stats_t)hxgep->statsp;

	mac_link_update(hxgep->mach, state);
	if (state == LINK_STATE_UP) {
		statsp->mac_stats.link_speed = 10000;
		statsp->mac_stats.link_duplex = 2;
		statsp->mac_stats.link_up = 1;
	} else {
		statsp->mac_stats.link_speed = 0;
		statsp->mac_stats.link_duplex = 0;
		statsp->mac_stats.link_up = 0;
	}
}
