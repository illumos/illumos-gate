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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SunOs MT STREAMS NIU/Neptune 10Gb Ethernet Device Driver.
 */
#include	<sys/nxge/nxge_impl.h>
#include	<sys/pcie.h>

uint32_t 	nxge_use_partition = 0;		/* debug partition flag */
uint32_t 	nxge_dma_obp_props_only = 1;	/* use obp published props */
uint32_t 	nxge_use_rdc_intr = 1;		/* debug to assign rdc intr */
/*
 * PSARC/2007/453 MSI-X interrupt limit override
 * (This PSARC case is limited to MSI-X vectors
 *  and SPARC platforms only).
 */
#if defined(_BIG_ENDIAN)
uint32_t	nxge_msi_enable = 2;
#else
uint32_t	nxge_msi_enable = 1;
#endif

/*
 * Globals: tunable parameters (/etc/system or adb)
 *
 */
uint32_t 	nxge_rbr_size = NXGE_RBR_RBB_DEFAULT;
uint32_t 	nxge_rbr_spare_size = 0;
uint32_t 	nxge_rcr_size = NXGE_RCR_DEFAULT;
uint32_t 	nxge_tx_ring_size = NXGE_TX_RING_DEFAULT;
boolean_t 	nxge_no_msg = B_TRUE;		/* control message display */
uint32_t 	nxge_no_link_notify = 0;	/* control DL_NOTIFY */
uint32_t 	nxge_bcopy_thresh = TX_BCOPY_MAX;
uint32_t 	nxge_dvma_thresh = TX_FASTDVMA_MIN;
uint32_t 	nxge_dma_stream_thresh = TX_STREAM_MIN;
uint32_t	nxge_jumbo_mtu	= TX_JUMBO_MTU;
boolean_t	nxge_jumbo_enable = B_FALSE;
uint16_t	nxge_rcr_timeout = NXGE_RDC_RCR_TIMEOUT;
uint16_t	nxge_rcr_threshold = NXGE_RDC_RCR_THRESHOLD;
nxge_tx_mode_t	nxge_tx_scheme = NXGE_USE_SERIAL;

/* MAX LSO size */
#define		NXGE_LSO_MAXLEN	65535
/* Enable Software LSO flag */
uint32_t	nxge_lso_enable = 1;
uint32_t	nxge_lso_max = NXGE_LSO_MAXLEN;

/*
 * Debugging flags:
 *		nxge_no_tx_lb : transmit load balancing
 *		nxge_tx_lb_policy: 0 - TCP port (default)
 *				   3 - DEST MAC
 */
uint32_t 	nxge_no_tx_lb = 0;
uint32_t 	nxge_tx_lb_policy = NXGE_TX_LB_TCPUDP;

/*
 * Add tunable to reduce the amount of time spent in the
 * ISR doing Rx Processing.
 */
uint32_t nxge_max_rx_pkts = 1024;

/*
 * Tunables to manage the receive buffer blocks.
 *
 * nxge_rx_threshold_hi: copy all buffers.
 * nxge_rx_bcopy_size_type: receive buffer block size type.
 * nxge_rx_threshold_lo: copy only up to tunable block size type.
 */
nxge_rxbuf_threshold_t nxge_rx_threshold_hi = NXGE_RX_COPY_6;
nxge_rxbuf_type_t nxge_rx_buf_size_type = RCR_PKTBUFSZ_0;
nxge_rxbuf_threshold_t nxge_rx_threshold_lo = NXGE_RX_COPY_3;

rtrace_t npi_rtracebuf;

#if	defined(sun4v)
/*
 * Hypervisor N2/NIU services information.
 */
static hsvc_info_t niu_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_NIU, NIU_MAJOR_VER,
	NIU_MINOR_VER, "nxge"
};
#endif

/*
 * Function Prototypes
 */
static int nxge_attach(dev_info_t *, ddi_attach_cmd_t);
static int nxge_detach(dev_info_t *, ddi_detach_cmd_t);
static void nxge_unattach(p_nxge_t);

#if NXGE_PROPERTY
static void nxge_remove_hard_properties(p_nxge_t);
#endif

static nxge_status_t nxge_setup_system_dma_pages(p_nxge_t);

static nxge_status_t nxge_setup_mutexes(p_nxge_t);
static void nxge_destroy_mutexes(p_nxge_t);

static nxge_status_t nxge_map_regs(p_nxge_t nxgep);
static void nxge_unmap_regs(p_nxge_t nxgep);
#ifdef	NXGE_DEBUG
static void nxge_test_map_regs(p_nxge_t nxgep);
#endif

static nxge_status_t nxge_add_intrs(p_nxge_t nxgep);
static nxge_status_t nxge_add_soft_intrs(p_nxge_t nxgep);
static void nxge_remove_intrs(p_nxge_t nxgep);
static void nxge_remove_soft_intrs(p_nxge_t nxgep);

static nxge_status_t nxge_add_intrs_adv(p_nxge_t nxgep);
static nxge_status_t nxge_add_intrs_adv_type(p_nxge_t, uint32_t);
static nxge_status_t nxge_add_intrs_adv_type_fix(p_nxge_t, uint32_t);
static void nxge_intrs_enable(p_nxge_t nxgep);
static void nxge_intrs_disable(p_nxge_t nxgep);

static void nxge_suspend(p_nxge_t);
static nxge_status_t nxge_resume(p_nxge_t);

static nxge_status_t nxge_setup_dev(p_nxge_t);
static void nxge_destroy_dev(p_nxge_t);

static nxge_status_t nxge_alloc_mem_pool(p_nxge_t);
static void nxge_free_mem_pool(p_nxge_t);

static nxge_status_t nxge_alloc_rx_mem_pool(p_nxge_t);
static void nxge_free_rx_mem_pool(p_nxge_t);

static nxge_status_t nxge_alloc_tx_mem_pool(p_nxge_t);
static void nxge_free_tx_mem_pool(p_nxge_t);

static nxge_status_t nxge_dma_mem_alloc(p_nxge_t, dma_method_t,
	struct ddi_dma_attr *,
	size_t, ddi_device_acc_attr_t *, uint_t,
	p_nxge_dma_common_t);

static void nxge_dma_mem_free(p_nxge_dma_common_t);

static nxge_status_t nxge_alloc_rx_buf_dma(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, size_t, size_t, uint32_t *);
static void nxge_free_rx_buf_dma(p_nxge_t, p_nxge_dma_common_t, uint32_t);

static nxge_status_t nxge_alloc_rx_cntl_dma(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, size_t);
static void nxge_free_rx_cntl_dma(p_nxge_t, p_nxge_dma_common_t);

static nxge_status_t nxge_alloc_tx_buf_dma(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, size_t, size_t, uint32_t *);
static void nxge_free_tx_buf_dma(p_nxge_t, p_nxge_dma_common_t, uint32_t);

static nxge_status_t nxge_alloc_tx_cntl_dma(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *,
	size_t);
static void nxge_free_tx_cntl_dma(p_nxge_t, p_nxge_dma_common_t);

static int nxge_init_common_dev(p_nxge_t);
static void nxge_uninit_common_dev(p_nxge_t);

/*
 * The next declarations are for the GLDv3 interface.
 */
static int nxge_m_start(void *);
static void nxge_m_stop(void *);
static int nxge_m_unicst(void *, const uint8_t *);
static int nxge_m_multicst(void *, boolean_t, const uint8_t *);
static int nxge_m_promisc(void *, boolean_t);
static void nxge_m_ioctl(void *, queue_t *, mblk_t *);
static void nxge_m_resources(void *);
mblk_t *nxge_m_tx(void *arg, mblk_t *);
static nxge_status_t nxge_mac_register(p_nxge_t);
static int nxge_altmac_set(p_nxge_t nxgep, uint8_t *mac_addr,
	mac_addr_slot_t slot);
static void nxge_mmac_kstat_update(p_nxge_t nxgep, mac_addr_slot_t slot,
	boolean_t factory);
static int nxge_m_mmac_add(void *arg, mac_multi_addr_t *maddr);
static int nxge_m_mmac_reserve(void *arg, mac_multi_addr_t *maddr);
static int nxge_m_mmac_remove(void *arg, mac_addr_slot_t slot);
static int nxge_m_mmac_modify(void *arg, mac_multi_addr_t *maddr);
static int nxge_m_mmac_get(void *arg, mac_multi_addr_t *maddr);

#define	NXGE_NEPTUNE_MAGIC	0x4E584745UL
#define	MAX_DUMP_SZ 256

#define	NXGE_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB)

static	boolean_t	nxge_m_getcapab(void *, mac_capab_t, void *);
static mac_callbacks_t nxge_m_callbacks = {
	NXGE_M_CALLBACK_FLAGS,
	nxge_m_stat,
	nxge_m_start,
	nxge_m_stop,
	nxge_m_promisc,
	nxge_m_multicst,
	nxge_m_unicst,
	nxge_m_tx,
	nxge_m_resources,
	nxge_m_ioctl,
	nxge_m_getcapab
};

void
nxge_err_inject(p_nxge_t, queue_t *, mblk_t *);

/* PSARC/2007/453 MSI-X interrupt limit override. */
#define	NXGE_MSIX_REQUEST_10G	8
#define	NXGE_MSIX_REQUEST_1G	2
static int nxge_create_msi_property(p_nxge_t);

/*
 * These global variables control the message
 * output.
 */
out_dbgmsg_t nxge_dbgmsg_out = DBG_CONSOLE | STR_LOG;
uint64_t nxge_debug_level = 0;

/*
 * This list contains the instance structures for the Neptune
 * devices present in the system. The lock exists to guarantee
 * mutually exclusive access to the list.
 */
void 			*nxge_list = NULL;

void			*nxge_hw_list = NULL;
nxge_os_mutex_t 	nxge_common_lock;

extern uint64_t 	npi_debug_level;

extern nxge_status_t	nxge_ldgv_init(p_nxge_t, int *, int *);
extern nxge_status_t	nxge_ldgv_init_n2(p_nxge_t, int *, int *);
extern nxge_status_t	nxge_ldgv_uninit(p_nxge_t);
extern nxge_status_t	nxge_intr_ldgv_init(p_nxge_t);
extern void		nxge_fm_init(p_nxge_t,
					ddi_device_acc_attr_t *,
					ddi_device_acc_attr_t *,
					ddi_dma_attr_t *);
extern void		nxge_fm_fini(p_nxge_t);
extern npi_status_t	npi_mac_altaddr_disable(npi_handle_t, uint8_t, uint8_t);

/*
 * Count used to maintain the number of buffers being used
 * by Neptune instances and loaned up to the upper layers.
 */
uint32_t nxge_mblks_pending = 0;

/*
 * Device register access attributes for PIO.
 */
static ddi_device_acc_attr_t nxge_dev_reg_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};

/*
 * Device descriptor access attributes for DMA.
 */
static ddi_device_acc_attr_t nxge_dev_desc_dma_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Device buffer access attributes for DMA.
 */
static ddi_device_acc_attr_t nxge_dev_buf_dma_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC
};

ddi_dma_attr_t nxge_desc_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
#ifndef NIU_PA_WORKAROUND
	0x100000,		/* alignment */
#else
	0x2000,
#endif
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(unsigned int) 1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t nxge_tx_dma_attr = {
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
	(unsigned int) 1,	/* granularity */
	0			/* attribute flags */
};

ddi_dma_attr_t nxge_rx_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	0,			/* low address */
	0xffffffffffffffff,	/* high address */
	0xffffffffffffffff,	/* address counter max */
	0x2000,			/* alignment */
	0xfc00fc,		/* dlim_burstsizes */
	0x1,			/* minimum transfer size */
	0xffffffffffffffff,	/* maximum transfer size */
	0xffffffffffffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	(unsigned int) 1,	/* granularity */
	DDI_DMA_RELAXED_ORDERING /* attribute flags */
};

ddi_dma_lim_t nxge_dma_limits = {
	(uint_t)0,		/* dlim_addr_lo */
	(uint_t)0xffffffff,	/* dlim_addr_hi */
	(uint_t)0xffffffff,	/* dlim_cntr_max */
	(uint_t)0xfc00fc,	/* dlim_burstsizes for 32 and 64 bit xfers */
	0x1,			/* dlim_minxfer */
	1024			/* dlim_speed */
};

dma_method_t nxge_force_dma = DVMA;

/*
 * dma chunk sizes.
 *
 * Try to allocate the largest possible size
 * so that fewer number of dma chunks would be managed
 */
#ifdef NIU_PA_WORKAROUND
size_t alloc_sizes [] = {0x2000};
#else
size_t alloc_sizes [] = {0x1000, 0x2000, 0x4000, 0x8000,
		0x10000, 0x20000, 0x40000, 0x80000,
		0x100000, 0x200000, 0x400000, 0x800000,
		0x1000000, 0x2000000, 0x4000000};
#endif

/*
 * Translate "dev_t" to a pointer to the associated "dev_info_t".
 */

static int
nxge_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	p_nxge_t	nxgep = NULL;
	int		instance;
	int		status = DDI_SUCCESS;
	uint8_t		portn;
	nxge_mmac_t	*mmac_info;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_attach"));

	/*
	 * Get the device instance since we'll need to setup
	 * or retrieve a soft state for this instance.
	 */
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing DDI_ATTACH"));
		break;

	case DDI_RESUME:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing DDI_RESUME"));
		nxgep = (p_nxge_t)ddi_get_soft_state(nxge_list, instance);
		if (nxgep == NULL) {
			status = DDI_FAILURE;
			break;
		}
		if (nxgep->dip != dip) {
			status = DDI_FAILURE;
			break;
		}
		if (nxgep->suspended == DDI_PM_SUSPEND) {
			status = ddi_dev_is_needed(nxgep->dip, 0, 1);
		} else {
			status = nxge_resume(nxgep);
		}
		goto nxge_attach_exit;

	case DDI_PM_RESUME:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing DDI_PM_RESUME"));
		nxgep = (p_nxge_t)ddi_get_soft_state(nxge_list, instance);
		if (nxgep == NULL) {
			status = DDI_FAILURE;
			break;
		}
		if (nxgep->dip != dip) {
			status = DDI_FAILURE;
			break;
		}
		status = nxge_resume(nxgep);
		goto nxge_attach_exit;

	default:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing unknown"));
		status = DDI_FAILURE;
		goto nxge_attach_exit;
	}


	if (ddi_soft_state_zalloc(nxge_list, instance) == DDI_FAILURE) {
		status = DDI_FAILURE;
		goto nxge_attach_exit;
	}

	nxgep = ddi_get_soft_state(nxge_list, instance);
	if (nxgep == NULL) {
		status = NXGE_ERROR;
		goto nxge_attach_fail2;
	}

	nxgep->nxge_magic = NXGE_MAGIC;

	nxgep->drv_state = 0;
	nxgep->dip = dip;
	nxgep->instance = instance;
	nxgep->p_dip = ddi_get_parent(dip);
	nxgep->nxge_debug_level = nxge_debug_level;
	npi_debug_level = nxge_debug_level;

	nxge_fm_init(nxgep, &nxge_dev_reg_acc_attr, &nxge_dev_desc_dma_acc_attr,
				&nxge_rx_dma_attr);

	status = nxge_map_regs(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_map_regs failed"));
		goto nxge_attach_fail3;
	}

	status = nxge_init_common_dev(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_init_common_dev failed"));
		goto nxge_attach_fail4;
	}

	if (nxgep->niu_type == NEPTUNE_2_10GF) {
		if (nxgep->function_num > 1) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Unsupported"
			    " function %d. Only functions 0 and 1 are "
			    "supported for this card.", nxgep->function_num));
			status = NXGE_ERROR;
			goto nxge_attach_fail4;
		}
	}

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);
	nxgep->mac.portnum = portn;
	if ((portn == 0) || (portn == 1))
		nxgep->mac.porttype = PORT_TYPE_XMAC;
	else
		nxgep->mac.porttype = PORT_TYPE_BMAC;
	/*
	 * Neptune has 4 ports, the first 2 ports use XMAC (10G MAC)
	 * internally, the rest 2 ports use BMAC (1G "Big" MAC).
	 * The two types of MACs have different characterizations.
	 */
	mmac_info = &nxgep->nxge_mmac_info;
	if (nxgep->function_num < 2) {
		mmac_info->num_mmac = XMAC_MAX_ALT_ADDR_ENTRY;
		mmac_info->naddrfree = XMAC_MAX_ALT_ADDR_ENTRY;
	} else {
		mmac_info->num_mmac = BMAC_MAX_ALT_ADDR_ENTRY;
		mmac_info->naddrfree = BMAC_MAX_ALT_ADDR_ENTRY;
	}
	/*
	 * Setup the Ndd parameters for the this instance.
	 */
	nxge_init_param(nxgep);

	/*
	 * Setup Register Tracing Buffer.
	 */
	npi_rtrace_buf_init((rtrace_t *)&npi_rtracebuf);

	/* init stats ptr */
	nxge_init_statsp(nxgep);

	/*
	 * read the vpd info from the eeprom into local data
	 * structure and check for the VPD info validity
	 */
	nxge_vpd_info_get(nxgep);

	status = nxge_xcvr_find(nxgep);

	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_attach: "
				    " Couldn't determine card type"
				    " .... exit "));
		goto nxge_attach_fail5;
	}

	status = nxge_get_config_properties(nxgep);

	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "get_hw create failed"));
		goto nxge_attach_fail;
	}

	/*
	 * Setup the Kstats for the driver.
	 */
	nxge_setup_kstats(nxgep);

	nxge_setup_param(nxgep);

	status = nxge_setup_system_dma_pages(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "set dma page failed"));
		goto nxge_attach_fail;
	}

#if	defined(sun4v)
	if (nxgep->niu_type == N2_NIU) {
		nxgep->niu_hsvc_available = B_FALSE;
		bcopy(&niu_hsvc, &nxgep->niu_hsvc, sizeof (hsvc_info_t));
		if ((status =
			hsvc_register(&nxgep->niu_hsvc,
					&nxgep->niu_min_ver)) != 0) {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					"nxge_attach: "
					"%s: cannot negotiate "
					"hypervisor services "
					"revision %d "
					"group: 0x%lx "
					"major: 0x%lx minor: 0x%lx "
					"errno: %d",
					niu_hsvc.hsvc_modname,
					niu_hsvc.hsvc_rev,
					niu_hsvc.hsvc_group,
					niu_hsvc.hsvc_major,
					niu_hsvc.hsvc_minor,
					status));
				status = DDI_FAILURE;
				goto nxge_attach_fail;
		}

		nxgep->niu_hsvc_available = B_TRUE;
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"NIU Hypervisor service enabled"));
	}
#endif

	nxge_hw_id_init(nxgep);
	nxge_hw_init_niu_common(nxgep);

	status = nxge_setup_mutexes(nxgep);
	if (status != NXGE_OK) {
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "set mutex failed"));
		goto nxge_attach_fail;
	}

	status = nxge_setup_dev(nxgep);
	if (status != DDI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "set dev failed"));
		goto nxge_attach_fail;
	}

	status = nxge_add_intrs(nxgep);
	if (status != DDI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "add_intr failed"));
		goto nxge_attach_fail;
	}
	status = nxge_add_soft_intrs(nxgep);
	if (status != DDI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, NXGE_ERR_CTL, "add_soft_intr failed"));
		goto nxge_attach_fail;
	}

	/*
	 * Enable interrupts.
	 */
	nxge_intrs_enable(nxgep);

	if ((status = nxge_mac_register(nxgep)) != NXGE_OK) {
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"unable to register to mac layer (%d)", status));
		goto nxge_attach_fail;
	}

	mac_link_update(nxgep->mach, LINK_STATE_UNKNOWN);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "registered to mac (instance %d)",
		instance));

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);

	goto nxge_attach_exit;

nxge_attach_fail:
	nxge_unattach(nxgep);
	goto nxge_attach_fail1;

nxge_attach_fail5:
	/*
	 * Tear down the ndd parameters setup.
	 */
	nxge_destroy_param(nxgep);

	/*
	 * Tear down the kstat setup.
	 */
	nxge_destroy_kstats(nxgep);

nxge_attach_fail4:
	if (nxgep->nxge_hw_p) {
		nxge_uninit_common_dev(nxgep);
		nxgep->nxge_hw_p = NULL;
	}

nxge_attach_fail3:
	/*
	 * Unmap the register setup.
	 */
	nxge_unmap_regs(nxgep);

	nxge_fm_fini(nxgep);

nxge_attach_fail2:
	ddi_soft_state_free(nxge_list, nxgep->instance);

nxge_attach_fail1:
	if (status != NXGE_OK)
		status = (NXGE_ERROR | NXGE_DDI_FAILED);
	nxgep = NULL;

nxge_attach_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_attach status = 0x%08x",
		status));

	return (status);
}

static int
nxge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int 		status = DDI_SUCCESS;
	int 		instance;
	p_nxge_t 	nxgep = NULL;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_detach"));
	instance = ddi_get_instance(dip);
	nxgep = ddi_get_soft_state(nxge_list, instance);
	if (nxgep == NULL) {
		status = DDI_FAILURE;
		goto nxge_detach_exit;
	}

	switch (cmd) {
	case DDI_DETACH:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing DDI_DETACH"));
		break;

	case DDI_PM_SUSPEND:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing DDI_PM_SUSPEND"));
		nxgep->suspended = DDI_PM_SUSPEND;
		nxge_suspend(nxgep);
		break;

	case DDI_SUSPEND:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "doing DDI_SUSPEND"));
		if (nxgep->suspended != DDI_PM_SUSPEND) {
			nxgep->suspended = DDI_SUSPEND;
			nxge_suspend(nxgep);
		}
		break;

	default:
		status = DDI_FAILURE;
	}

	if (cmd != DDI_DETACH)
		goto nxge_detach_exit;

	/*
	 * Stop the xcvr polling.
	 */
	nxgep->suspended = cmd;

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_STOP);

	if (nxgep->mach && (status = mac_unregister(nxgep->mach)) != 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_detach status = 0x%08X", status));
		return (DDI_FAILURE);
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		"<== nxge_detach (mac_unregister) status = 0x%08X", status));

	nxge_unattach(nxgep);
	nxgep = NULL;

nxge_detach_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_detach status = 0x%08X",
		status));

	return (status);
}

static void
nxge_unattach(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_unattach"));

	if (nxgep == NULL || nxgep->dev_regs == NULL) {
		return;
	}

	nxgep->nxge_magic = 0;

	if (nxgep->nxge_timerid) {
		nxge_stop_timer(nxgep, nxgep->nxge_timerid);
		nxgep->nxge_timerid = 0;
	}

	if (nxgep->nxge_hw_p) {
		nxge_uninit_common_dev(nxgep);
		nxgep->nxge_hw_p = NULL;
	}

#if	defined(sun4v)
	if (nxgep->niu_type == N2_NIU && nxgep->niu_hsvc_available == B_TRUE) {
		(void) hsvc_unregister(&nxgep->niu_hsvc);
		nxgep->niu_hsvc_available = B_FALSE;
	}
#endif
	/*
	 * Stop any further interrupts.
	 */
	nxge_remove_intrs(nxgep);

	/* remove soft interrups */
	nxge_remove_soft_intrs(nxgep);

	/*
	 * Stop the device and free resources.
	 */
	nxge_destroy_dev(nxgep);

	/*
	 * Tear down the ndd parameters setup.
	 */
	nxge_destroy_param(nxgep);

	/*
	 * Tear down the kstat setup.
	 */
	nxge_destroy_kstats(nxgep);

	/*
	 * Destroy all mutexes.
	 */
	nxge_destroy_mutexes(nxgep);

	/*
	 * Remove the list of ndd parameters which
	 * were setup during attach.
	 */
	if (nxgep->dip) {
		NXGE_DEBUG_MSG((nxgep, OBP_CTL,
				    " nxge_unattach: remove all properties"));

		(void) ddi_prop_remove_all(nxgep->dip);
	}

#if NXGE_PROPERTY
	nxge_remove_hard_properties(nxgep);
#endif

	/*
	 * Unmap the register setup.
	 */
	nxge_unmap_regs(nxgep);

	nxge_fm_fini(nxgep);

	ddi_soft_state_free(nxge_list, nxgep->instance);

	NXGE_DEBUG_MSG((NULL, DDI_CTL, "<== nxge_unattach"));
}

static char n2_siu_name[] = "niu";

static nxge_status_t
nxge_map_regs(p_nxge_t nxgep)
{
	int		ddi_status = DDI_SUCCESS;
	p_dev_regs_t 	dev_regs;
	char		buf[MAXPATHLEN + 1];
	char 		*devname;
#ifdef	NXGE_DEBUG
	char 		*sysname;
#endif
	off_t		regsize;
	nxge_status_t	status = NXGE_OK;
#if !defined(_BIG_ENDIAN)
	off_t pci_offset;
	uint16_t pcie_devctl;
#endif

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_map_regs"));
	nxgep->dev_regs = NULL;
	dev_regs = KMEM_ZALLOC(sizeof (dev_regs_t), KM_SLEEP);
	dev_regs->nxge_regh = NULL;
	dev_regs->nxge_pciregh = NULL;
	dev_regs->nxge_msix_regh = NULL;
	dev_regs->nxge_vir_regh = NULL;
	dev_regs->nxge_vir2_regh = NULL;
	nxgep->niu_type = NIU_TYPE_NONE;

	devname = ddi_pathname(nxgep->dip, buf);
	ASSERT(strlen(devname) > 0);
	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		"nxge_map_regs: pathname devname %s", devname));

	if (strstr(devname, n2_siu_name)) {
		/* N2/NIU */
		nxgep->niu_type = N2_NIU;
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: N2/NIU devname %s", devname));
		/* get function number */
		nxgep->function_num =
			(devname[strlen(devname) -1] == '1' ? 1 : 0);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: N2/NIU function number %d",
			nxgep->function_num));
	} else {
		int		*prop_val;
		uint_t 		prop_len;
		uint8_t 	func_num;

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, nxgep->dip,
				0, "reg",
				&prop_val, &prop_len) != DDI_PROP_SUCCESS) {
			NXGE_DEBUG_MSG((nxgep, VPD_CTL,
				"Reg property not found"));
			ddi_status = DDI_FAILURE;
			goto nxge_map_regs_fail0;

		} else {
			func_num = (prop_val[0] >> 8) & 0x7;
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"Reg property found: fun # %d",
				func_num));
			nxgep->function_num = func_num;
			ddi_prop_free(prop_val);
		}
	}

	switch (nxgep->niu_type) {
	default:
		(void) ddi_dev_regsize(nxgep->dip, 0, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: pci config size 0x%x", regsize));

		ddi_status = ddi_regs_map_setup(nxgep->dip, 0,
			(caddr_t *)&(dev_regs->nxge_pciregp), 0, 0,
			&nxge_dev_reg_acc_attr, &dev_regs->nxge_pciregh);
		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs, nxge bus config regs failed"));
			goto nxge_map_regs_fail0;
		}
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_reg: PCI config addr 0x%0llx "
			" handle 0x%0llx", dev_regs->nxge_pciregp,
			dev_regs->nxge_pciregh));
			/*
			 * IMP IMP
			 * workaround  for bit swapping bug in HW
			 * which ends up in no-snoop = yes
			 * resulting, in DMA not synched properly
			 */
#if !defined(_BIG_ENDIAN)
		/* workarounds for x86 systems */
		pci_offset = 0x80 + PCIE_DEVCTL;
		pcie_devctl = 0x0;
		pcie_devctl &= PCIE_DEVCTL_ENABLE_NO_SNOOP;
		pcie_devctl |= PCIE_DEVCTL_RO_EN;
		pci_config_put16(dev_regs->nxge_pciregh, pci_offset,
				    pcie_devctl);
#endif

		(void) ddi_dev_regsize(nxgep->dip, 1, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: pio size 0x%x", regsize));
		/* set up the device mapped register */
		ddi_status = ddi_regs_map_setup(nxgep->dip, 1,
			(caddr_t *)&(dev_regs->nxge_regp), 0, 0,
			&nxge_dev_reg_acc_attr, &dev_regs->nxge_regh);
		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs for Neptune global reg failed"));
			goto nxge_map_regs_fail1;
		}

		/* set up the msi/msi-x mapped register */
		(void) ddi_dev_regsize(nxgep->dip, 2, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: msix size 0x%x", regsize));
		ddi_status = ddi_regs_map_setup(nxgep->dip, 2,
			(caddr_t *)&(dev_regs->nxge_msix_regp), 0, 0,
			&nxge_dev_reg_acc_attr, &dev_regs->nxge_msix_regh);
		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs for msi reg failed"));
			goto nxge_map_regs_fail2;
		}

		/* set up the vio region mapped register */
		(void) ddi_dev_regsize(nxgep->dip, 3, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: vio size 0x%x", regsize));
		ddi_status = ddi_regs_map_setup(nxgep->dip, 3,
			(caddr_t *)&(dev_regs->nxge_vir_regp), 0, 0,
			&nxge_dev_reg_acc_attr, &dev_regs->nxge_vir_regh);

		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs for nxge vio reg failed"));
			goto nxge_map_regs_fail3;
		}
		nxgep->dev_regs = dev_regs;

		NPI_PCI_ACC_HANDLE_SET(nxgep, dev_regs->nxge_pciregh);
		NPI_PCI_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_pciregp);
		NPI_MSI_ACC_HANDLE_SET(nxgep, dev_regs->nxge_msix_regh);
		NPI_MSI_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_msix_regp);

		NPI_ACC_HANDLE_SET(nxgep, dev_regs->nxge_regh);
		NPI_ADD_HANDLE_SET(nxgep, (npi_reg_ptr_t)dev_regs->nxge_regp);

		NPI_REG_ACC_HANDLE_SET(nxgep, dev_regs->nxge_regh);
		NPI_REG_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_regp);

		NPI_VREG_ACC_HANDLE_SET(nxgep, dev_regs->nxge_vir_regh);
		NPI_VREG_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_vir_regp);

		break;

	case N2_NIU:
		NXGE_DEBUG_MSG((nxgep, DDI_CTL, "ddi_map_regs, NIU"));
		/*
		 * Set up the device mapped register (FWARC 2006/556)
		 * (changed back to 1: reg starts at 1!)
		 */
		(void) ddi_dev_regsize(nxgep->dip, 1, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: dev size 0x%x", regsize));
		ddi_status = ddi_regs_map_setup(nxgep->dip, 1,
				(caddr_t *)&(dev_regs->nxge_regp), 0, 0,
				&nxge_dev_reg_acc_attr, &dev_regs->nxge_regh);

		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs for N2/NIU, global reg failed "));
			goto nxge_map_regs_fail1;
		}

		/* set up the vio region mapped register */
		(void) ddi_dev_regsize(nxgep->dip, 2, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: vio (1) size 0x%x", regsize));
		ddi_status = ddi_regs_map_setup(nxgep->dip, 2,
			(caddr_t *)&(dev_regs->nxge_vir_regp), 0, 0,
			&nxge_dev_reg_acc_attr, &dev_regs->nxge_vir_regh);

		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs for nxge vio reg failed"));
			goto nxge_map_regs_fail2;
		}
		/* set up the vio region mapped register */
		(void) ddi_dev_regsize(nxgep->dip, 3, &regsize);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"nxge_map_regs: vio (3) size 0x%x", regsize));
		ddi_status = ddi_regs_map_setup(nxgep->dip, 3,
			(caddr_t *)&(dev_regs->nxge_vir2_regp), 0, 0,
			&nxge_dev_reg_acc_attr, &dev_regs->nxge_vir2_regh);

		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"ddi_map_regs for nxge vio2 reg failed"));
			goto nxge_map_regs_fail3;
		}
		nxgep->dev_regs = dev_regs;

		NPI_ACC_HANDLE_SET(nxgep, dev_regs->nxge_regh);
		NPI_ADD_HANDLE_SET(nxgep, (npi_reg_ptr_t)dev_regs->nxge_regp);

		NPI_REG_ACC_HANDLE_SET(nxgep, dev_regs->nxge_regh);
		NPI_REG_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_regp);

		NPI_VREG_ACC_HANDLE_SET(nxgep, dev_regs->nxge_vir_regh);
		NPI_VREG_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_vir_regp);

		NPI_V2REG_ACC_HANDLE_SET(nxgep, dev_regs->nxge_vir2_regh);
		NPI_V2REG_ADD_HANDLE_SET(nxgep,
			(npi_reg_ptr_t)dev_regs->nxge_vir2_regp);

		break;
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "nxge_map_reg: hardware addr 0x%0llx "
		" handle 0x%0llx", dev_regs->nxge_regp, dev_regs->nxge_regh));

	goto nxge_map_regs_exit;
nxge_map_regs_fail3:
	if (dev_regs->nxge_msix_regh) {
		ddi_regs_map_free(&dev_regs->nxge_msix_regh);
	}
	if (dev_regs->nxge_vir_regh) {
		ddi_regs_map_free(&dev_regs->nxge_regh);
	}
nxge_map_regs_fail2:
	if (dev_regs->nxge_regh) {
		ddi_regs_map_free(&dev_regs->nxge_regh);
	}
nxge_map_regs_fail1:
	if (dev_regs->nxge_pciregh) {
		ddi_regs_map_free(&dev_regs->nxge_pciregh);
	}
nxge_map_regs_fail0:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "Freeing register set memory"));
	kmem_free(dev_regs, sizeof (dev_regs_t));

nxge_map_regs_exit:
	if (ddi_status != DDI_SUCCESS)
		status |= (NXGE_ERROR | NXGE_DDI_FAILED);
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_map_regs"));
	return (status);
}

static void
nxge_unmap_regs(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_unmap_regs"));
	if (nxgep->dev_regs) {
		if (nxgep->dev_regs->nxge_pciregh) {
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"==> nxge_unmap_regs: bus"));
			ddi_regs_map_free(&nxgep->dev_regs->nxge_pciregh);
			nxgep->dev_regs->nxge_pciregh = NULL;
		}
		if (nxgep->dev_regs->nxge_regh) {
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"==> nxge_unmap_regs: device registers"));
			ddi_regs_map_free(&nxgep->dev_regs->nxge_regh);
			nxgep->dev_regs->nxge_regh = NULL;
		}
		if (nxgep->dev_regs->nxge_msix_regh) {
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"==> nxge_unmap_regs: device interrupts"));
			ddi_regs_map_free(&nxgep->dev_regs->nxge_msix_regh);
			nxgep->dev_regs->nxge_msix_regh = NULL;
		}
		if (nxgep->dev_regs->nxge_vir_regh) {
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"==> nxge_unmap_regs: vio region"));
			ddi_regs_map_free(&nxgep->dev_regs->nxge_vir_regh);
			nxgep->dev_regs->nxge_vir_regh = NULL;
		}
		if (nxgep->dev_regs->nxge_vir2_regh) {
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"==> nxge_unmap_regs: vio2 region"));
			ddi_regs_map_free(&nxgep->dev_regs->nxge_vir2_regh);
			nxgep->dev_regs->nxge_vir2_regh = NULL;
		}

		kmem_free(nxgep->dev_regs, sizeof (dev_regs_t));
		nxgep->dev_regs = NULL;
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_unmap_regs"));
}

static nxge_status_t
nxge_setup_mutexes(p_nxge_t nxgep)
{
	int ddi_status = DDI_SUCCESS;
	nxge_status_t status = NXGE_OK;
	nxge_classify_t *classify_ptr;
	int partition;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_setup_mutexes"));

	/*
	 * Get the interrupt cookie so the mutexes can be
	 * Initialized.
	 */
	ddi_status = ddi_get_iblock_cookie(nxgep->dip, 0,
					&nxgep->interrupt_cookie);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_setup_mutexes: failed 0x%x", ddi_status));
		goto nxge_setup_mutexes_exit;
	}

	cv_init(&nxgep->poll_cv, NULL, CV_DRIVER, NULL);
	MUTEX_INIT(&nxgep->poll_lock, NULL,
	    MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);

	/*
	 * Initialize mutexes for this device.
	 */
	MUTEX_INIT(nxgep->genlock, NULL,
		MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);
	MUTEX_INIT(&nxgep->ouraddr_lock, NULL,
		MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);
	MUTEX_INIT(&nxgep->mif_lock, NULL,
		MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);
	RW_INIT(&nxgep->filter_lock, NULL,
		RW_DRIVER, (void *)nxgep->interrupt_cookie);

	classify_ptr = &nxgep->classifier;
		/*
		 * FFLP Mutexes are never used in interrupt context
		 * as fflp operation can take very long time to
		 * complete and hence not suitable to invoke from interrupt
		 * handlers.
		 */
	MUTEX_INIT(&classify_ptr->tcam_lock, NULL,
	    NXGE_MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);
	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		MUTEX_INIT(&classify_ptr->fcram_lock, NULL,
		    NXGE_MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);
		for (partition = 0; partition < MAX_PARTITION; partition++) {
			MUTEX_INIT(&classify_ptr->hash_lock[partition], NULL,
			    NXGE_MUTEX_DRIVER, (void *)nxgep->interrupt_cookie);
		}
	}

nxge_setup_mutexes_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
	    "<== nxge_setup_mutexes status = %x", status));

	if (ddi_status != DDI_SUCCESS)
		status |= (NXGE_ERROR | NXGE_DDI_FAILED);

	return (status);
}

static void
nxge_destroy_mutexes(p_nxge_t nxgep)
{
	int partition;
	nxge_classify_t *classify_ptr;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_destroy_mutexes"));
	RW_DESTROY(&nxgep->filter_lock);
	MUTEX_DESTROY(&nxgep->mif_lock);
	MUTEX_DESTROY(&nxgep->ouraddr_lock);
	MUTEX_DESTROY(nxgep->genlock);

	classify_ptr = &nxgep->classifier;
	MUTEX_DESTROY(&classify_ptr->tcam_lock);

	/* Destroy all polling resources. */
	MUTEX_DESTROY(&nxgep->poll_lock);
	cv_destroy(&nxgep->poll_cv);

	/* free data structures, based on HW type */
	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		MUTEX_DESTROY(&classify_ptr->fcram_lock);
		for (partition = 0; partition < MAX_PARTITION; partition++) {
			MUTEX_DESTROY(&classify_ptr->hash_lock[partition]);
		}
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_destroy_mutexes"));
}

nxge_status_t
nxge_init(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, STR_CTL, "==> nxge_init"));

	if (nxgep->drv_state & STATE_HW_INITIALIZED) {
		return (status);
	}

	/*
	 * Allocate system memory for the receive/transmit buffer blocks
	 * and receive/transmit descriptor rings.
	 */
	status = nxge_alloc_mem_pool(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "alloc mem failed\n"));
		goto nxge_init_fail1;
	}

	/*
	 * Initialize and enable TXC registers
	 * (Globally enable TX controller,
	 *  enable a port, configure dma channel bitmap,
	 *  configure the max burst size).
	 */
	status = nxge_txc_init(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init txc failed\n"));
		goto nxge_init_fail2;
	}

	/*
	 * Initialize and enable TXDMA channels.
	 */
	status = nxge_init_txdma_channels(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init txdma failed\n"));
		goto nxge_init_fail3;
	}

	/*
	 * Initialize and enable RXDMA channels.
	 */
	status = nxge_init_rxdma_channels(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init rxdma failed\n"));
		goto nxge_init_fail4;
	}

	/*
	 * Initialize TCAM and FCRAM (Neptune).
	 */
	status = nxge_classify_init(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init classify failed\n"));
		goto nxge_init_fail5;
	}

	/*
	 * Initialize ZCP
	 */
	status = nxge_zcp_init(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init ZCP failed\n"));
		goto nxge_init_fail5;
	}

	/*
	 * Initialize IPP.
	 */
	status = nxge_ipp_init(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init IPP failed\n"));
		goto nxge_init_fail5;
	}

	/*
	 * Initialize the MAC block.
	 */
	status = nxge_mac_init(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "init MAC failed\n"));
		goto nxge_init_fail5;
	}

	nxge_intrs_enable(nxgep);

	/*
	 * Enable hardware interrupts.
	 */
	nxge_intr_hw_enable(nxgep);
	nxgep->drv_state |= STATE_HW_INITIALIZED;

	goto nxge_init_exit;

nxge_init_fail5:
	nxge_uninit_rxdma_channels(nxgep);
nxge_init_fail4:
	nxge_uninit_txdma_channels(nxgep);
nxge_init_fail3:
	(void) nxge_txc_uninit(nxgep);
nxge_init_fail2:
	nxge_free_mem_pool(nxgep);
nxge_init_fail1:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		"<== nxge_init status (failed) = 0x%08x", status));
	return (status);

nxge_init_exit:

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_init status = 0x%08x",
		status));
	return (status);
}


timeout_id_t
nxge_start_timer(p_nxge_t nxgep, fptrv_t func, int msec)
{
	if ((nxgep->suspended == 0) ||
			(nxgep->suspended == DDI_RESUME)) {
		return (timeout(func, (caddr_t)nxgep,
			drv_usectohz(1000 * msec)));
	}
	return (NULL);
}

/*ARGSUSED*/
void
nxge_stop_timer(p_nxge_t nxgep, timeout_id_t timerid)
{
	if (timerid) {
		(void) untimeout(timerid);
	}
}

void
nxge_uninit(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_uninit"));

	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"==> nxge_uninit: not initialized"));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"<== nxge_uninit"));
		return;
	}

	/* stop timer */
	if (nxgep->nxge_timerid) {
		nxge_stop_timer(nxgep, nxgep->nxge_timerid);
		nxgep->nxge_timerid = 0;
	}

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_STOP);
	(void) nxge_intr_hw_disable(nxgep);

	/*
	 * Reset the receive MAC side.
	 */
	(void) nxge_rx_mac_disable(nxgep);

	/* Disable and soft reset the IPP */
	(void) nxge_ipp_disable(nxgep);

	/* Free classification resources */
	(void) nxge_classify_uninit(nxgep);

	/*
	 * Reset the transmit/receive DMA side.
	 */
	(void) nxge_txdma_hw_mode(nxgep, NXGE_DMA_STOP);
	(void) nxge_rxdma_hw_mode(nxgep, NXGE_DMA_STOP);

	nxge_uninit_txdma_channels(nxgep);
	nxge_uninit_rxdma_channels(nxgep);

	/*
	 * Reset the transmit MAC side.
	 */
	(void) nxge_tx_mac_disable(nxgep);

	nxge_free_mem_pool(nxgep);

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);

	nxgep->drv_state &= ~STATE_HW_INITIALIZED;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_uninit: "
		"nxge_mblks_pending %d", nxge_mblks_pending));
}

void
nxge_get64(p_nxge_t nxgep, p_mblk_t mp)
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
		NXGE_REG_RD64(nxgep->npi_handle, reg, &regdata);
	}
	bcopy((char *)&regdata, (char *)mp->b_rptr, sizeof (uint64_t));
}

void
nxge_put64(p_nxge_t nxgep, p_mblk_t mp)
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

	NXGE_NPI_PIO_WRITE64(nxgep->npi_handle, reg, buf[1]);
}


nxge_os_mutex_t nxgedebuglock;
int nxge_debug_init = 0;

/*ARGSUSED*/
/*VARARGS*/
void
nxge_debug_msg(p_nxge_t nxgep, uint64_t level, char *fmt, ...)
{
	char msg_buffer[1048];
	char prefix_buffer[32];
	int instance;
	uint64_t debug_level;
	int cmn_level = CE_CONT;
	va_list ap;

	debug_level = (nxgep == NULL) ? nxge_debug_level :
		nxgep->nxge_debug_level;

	if ((level & debug_level) ||
		(level == NXGE_NOTE) ||
		(level == NXGE_ERR_CTL)) {
		/* do the msg processing */
		if (nxge_debug_init == 0) {
			MUTEX_INIT(&nxgedebuglock, NULL, MUTEX_DRIVER, NULL);
			nxge_debug_init = 1;
		}

		MUTEX_ENTER(&nxgedebuglock);

		if ((level & NXGE_NOTE)) {
			cmn_level = CE_NOTE;
		}

		if (level & NXGE_ERR_CTL) {
			cmn_level = CE_WARN;
		}

		va_start(ap, fmt);
		(void) vsprintf(msg_buffer, fmt, ap);
		va_end(ap);
		if (nxgep == NULL) {
			instance = -1;
			(void) sprintf(prefix_buffer, "%s :", "nxge");
		} else {
			instance = nxgep->instance;
			(void) sprintf(prefix_buffer,
						    "%s%d :", "nxge", instance);
		}

		MUTEX_EXIT(&nxgedebuglock);
		cmn_err(cmn_level, "!%s %s\n",
				prefix_buffer, msg_buffer);

	}
}

char *
nxge_dump_packet(char *addr, int size)
{
	uchar_t *ap = (uchar_t *)addr;
	int i;
	static char etherbuf[1024];
	char *cp = etherbuf;
	char digits[] = "0123456789abcdef";

	if (!size)
		size = 60;

	if (size > MAX_DUMP_SZ) {
		/* Dump the leading bytes */
		for (i = 0; i < MAX_DUMP_SZ/2; i++) {
			if (*ap > 0x0f)
				*cp++ = digits[*ap >> 4];
			*cp++ = digits[*ap++ & 0xf];
			*cp++ = ':';
		}
		for (i = 0; i < 20; i++)
			*cp++ = '.';
		/* Dump the last MAX_DUMP_SZ/2 bytes */
		ap = (uchar_t *)(addr + (size - MAX_DUMP_SZ/2));
		for (i = 0; i < MAX_DUMP_SZ/2; i++) {
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

#ifdef	NXGE_DEBUG
static void
nxge_test_map_regs(p_nxge_t nxgep)
{
	ddi_acc_handle_t cfg_handle;
	p_pci_cfg_t	cfg_ptr;
	ddi_acc_handle_t dev_handle;
	char		*dev_ptr;
	ddi_acc_handle_t pci_config_handle;
	uint32_t	regval;
	int		i;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_test_map_regs"));

	dev_handle = nxgep->dev_regs->nxge_regh;
	dev_ptr = (char *)nxgep->dev_regs->nxge_regp;

	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		cfg_handle = nxgep->dev_regs->nxge_pciregh;
		cfg_ptr = (void *)nxgep->dev_regs->nxge_pciregp;

		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "Neptune PCI regp cfg_ptr 0x%llx", (char *)cfg_ptr));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "Neptune PCI cfg_ptr vendor id ptr 0x%llx",
		    &cfg_ptr->vendorid));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "\tvendorid 0x%x devid 0x%x",
		    NXGE_PIO_READ16(cfg_handle, &cfg_ptr->vendorid, 0),
		    NXGE_PIO_READ16(cfg_handle, &cfg_ptr->devid,    0)));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "PCI BAR: base 0x%x base14 0x%x base 18 0x%x "
		    "bar1c 0x%x",
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base,   0),
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base14, 0),
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base18, 0),
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base1c, 0)));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "\nNeptune PCI BAR: base20 0x%x base24 0x%x "
		    "base 28 0x%x bar2c 0x%x\n",
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base20, 0),
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base24, 0),
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base28, 0),
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base2c, 0)));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "\nNeptune PCI BAR: base30 0x%x\n",
		    NXGE_PIO_READ32(cfg_handle, &cfg_ptr->base30, 0)));

		cfg_handle = nxgep->dev_regs->nxge_pciregh;
		cfg_ptr = (void *)nxgep->dev_regs->nxge_pciregp;
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		    "first  0x%llx second 0x%llx third 0x%llx "
		    "last 0x%llx ",
		    NXGE_PIO_READ64(dev_handle,
		    (uint64_t *)(dev_ptr + 0),  0),
		    NXGE_PIO_READ64(dev_handle,
		    (uint64_t *)(dev_ptr + 8),  0),
		    NXGE_PIO_READ64(dev_handle,
		    (uint64_t *)(dev_ptr + 16), 0),
		    NXGE_PIO_READ64(cfg_handle,
		    (uint64_t *)(dev_ptr + 24), 0)));
	}
}

#endif

static void
nxge_suspend(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_suspend"));

	nxge_intrs_disable(nxgep);
	nxge_destroy_dev(nxgep);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_suspend"));
}

static nxge_status_t
nxge_resume(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_resume"));

	nxgep->suspended = DDI_RESUME;
	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);
	(void) nxge_rxdma_hw_mode(nxgep, NXGE_DMA_START);
	(void) nxge_txdma_hw_mode(nxgep, NXGE_DMA_START);
	(void) nxge_rx_mac_enable(nxgep);
	(void) nxge_tx_mac_enable(nxgep);
	nxge_intrs_enable(nxgep);
	nxgep->suspended = 0;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"<== nxge_resume status = 0x%x", status));
	return (status);
}

static nxge_status_t
nxge_setup_dev(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_setup_dev port %d",
	    nxgep->mac.portnum));

	status = nxge_link_init(nxgep);

	if (fm_check_acc_handle(nxgep->dev_regs->nxge_regh) != DDI_FM_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"port%d Bad register acc handle", nxgep->mac.portnum));
		status = NXGE_ERROR;
	}

	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    " nxge_setup_dev status "
			    "(xcvr init 0x%08x)", status));
		goto nxge_setup_dev_exit;
	}

nxge_setup_dev_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		"<== nxge_setup_dev port %d status = 0x%08x",
		nxgep->mac.portnum, status));

	return (status);
}

static void
nxge_destroy_dev(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_destroy_dev"));

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_STOP);

	(void) nxge_hw_stop(nxgep);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_destroy_dev"));
}

static nxge_status_t
nxge_setup_system_dma_pages(p_nxge_t nxgep)
{
	int 			ddi_status = DDI_SUCCESS;
	uint_t 			count;
	ddi_dma_cookie_t 	cookie;
	uint_t 			iommu_pagesize;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_setup_system_dma_pages"));
	nxgep->sys_page_sz = ddi_ptob(nxgep->dip, (ulong_t)1);
	if (nxgep->niu_type != N2_NIU) {
		iommu_pagesize = dvma_pagesize(nxgep->dip);
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			" nxge_setup_system_dma_pages: page %d (ddi_ptob %d) "
			" default_block_size %d iommu_pagesize %d",
			nxgep->sys_page_sz,
			ddi_ptob(nxgep->dip, (ulong_t)1),
			nxgep->rx_default_block_size,
			iommu_pagesize));

		if (iommu_pagesize != 0) {
			if (nxgep->sys_page_sz == iommu_pagesize) {
				if (iommu_pagesize > 0x4000)
					nxgep->sys_page_sz = 0x4000;
			} else {
				if (nxgep->sys_page_sz > iommu_pagesize)
					nxgep->sys_page_sz = iommu_pagesize;
			}
		}
	}
	nxgep->sys_page_mask = ~(nxgep->sys_page_sz - 1);
	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		"==> nxge_setup_system_dma_pages: page %d (ddi_ptob %d) "
		"default_block_size %d page mask %d",
		nxgep->sys_page_sz,
		ddi_ptob(nxgep->dip, (ulong_t)1),
		nxgep->rx_default_block_size,
		nxgep->sys_page_mask));


	switch (nxgep->sys_page_sz) {
	default:
		nxgep->sys_page_sz = 0x1000;
		nxgep->sys_page_mask = ~(nxgep->sys_page_sz - 1);
		nxgep->rx_default_block_size = 0x1000;
		nxgep->rx_bksize_code = RBR_BKSIZE_4K;
		break;
	case 0x1000:
		nxgep->rx_default_block_size = 0x1000;
		nxgep->rx_bksize_code = RBR_BKSIZE_4K;
		break;
	case 0x2000:
		nxgep->rx_default_block_size = 0x2000;
		nxgep->rx_bksize_code = RBR_BKSIZE_8K;
		break;
	case 0x4000:
		nxgep->rx_default_block_size = 0x4000;
		nxgep->rx_bksize_code = RBR_BKSIZE_16K;
		break;
	case 0x8000:
		nxgep->rx_default_block_size = 0x8000;
		nxgep->rx_bksize_code = RBR_BKSIZE_32K;
		break;
	}

#ifndef USE_RX_BIG_BUF
	nxge_rx_dma_attr.dma_attr_align = nxgep->sys_page_sz;
#else
		nxgep->rx_default_block_size = 0x2000;
		nxgep->rx_bksize_code = RBR_BKSIZE_8K;
#endif
	/*
	 * Get the system DMA burst size.
	 */
	ddi_status = ddi_dma_alloc_handle(nxgep->dip, &nxge_tx_dma_attr,
			DDI_DMA_DONTWAIT, 0,
			&nxgep->dmasparehandle);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"ddi_dma_alloc_handle: failed "
			" status 0x%x", ddi_status));
		goto nxge_get_soft_properties_exit;
	}

	ddi_status = ddi_dma_addr_bind_handle(nxgep->dmasparehandle, NULL,
				(caddr_t)nxgep->dmasparehandle,
				sizeof (nxgep->dmasparehandle),
				DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
				DDI_DMA_DONTWAIT, 0,
				&cookie, &count);
	if (ddi_status != DDI_DMA_MAPPED) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"Binding spare handle to find system"
			" burstsize failed."));
		ddi_status = DDI_FAILURE;
		goto nxge_get_soft_properties_fail1;
	}

	nxgep->sys_burst_sz = ddi_dma_burstsizes(nxgep->dmasparehandle);
	(void) ddi_dma_unbind_handle(nxgep->dmasparehandle);

nxge_get_soft_properties_fail1:
	ddi_dma_free_handle(&nxgep->dmasparehandle);

nxge_get_soft_properties_exit:

	if (ddi_status != DDI_SUCCESS)
		status |= (NXGE_ERROR | NXGE_DDI_FAILED);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		"<== nxge_setup_system_dma_pages status = 0x%08x", status));
	return (status);
}

static nxge_status_t
nxge_alloc_mem_pool(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_alloc_mem_pool"));

	status = nxge_alloc_rx_mem_pool(nxgep);
	if (status != NXGE_OK) {
		return (NXGE_ERROR);
	}

	status = nxge_alloc_tx_mem_pool(nxgep);
	if (status != NXGE_OK) {
		nxge_free_rx_mem_pool(nxgep);
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_alloc_mem_pool"));
	return (NXGE_OK);
}

static void
nxge_free_mem_pool(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, MEM_CTL, "==> nxge_free_mem_pool"));

	nxge_free_rx_mem_pool(nxgep);
	nxge_free_tx_mem_pool(nxgep);

	NXGE_DEBUG_MSG((nxgep, MEM_CTL, "<== nxge_free_mem_pool"));
}

static nxge_status_t
nxge_alloc_rx_mem_pool(p_nxge_t nxgep)
{
	int			i, j;
	uint32_t		ndmas, st_rdc;
	p_nxge_dma_pt_cfg_t	p_all_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	p_nxge_dma_pool_t	dma_poolp;
	p_nxge_dma_common_t	*dma_buf_p;
	p_nxge_dma_pool_t	dma_cntl_poolp;
	p_nxge_dma_common_t	*dma_cntl_p;
	size_t			rx_buf_alloc_size;
	size_t			rx_cntl_alloc_size;
	uint32_t 		*num_chunks; /* per dma */
	nxge_status_t		status = NXGE_OK;

	uint32_t		nxge_port_rbr_size;
	uint32_t		nxge_port_rbr_spare_size;
	uint32_t		nxge_port_rcr_size;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_alloc_rx_mem_pool"));

	p_all_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;
	st_rdc = p_cfgp->start_rdc;
	ndmas = p_cfgp->max_rdcs;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		" nxge_alloc_rx_mem_pool st_rdc %d ndmas %d", st_rdc, ndmas));

	/*
	 * Allocate memory for each receive DMA channel.
	 */
	dma_poolp = (p_nxge_dma_pool_t)KMEM_ZALLOC(sizeof (nxge_dma_pool_t),
			KM_SLEEP);
	dma_buf_p = (p_nxge_dma_common_t *)KMEM_ZALLOC(
			sizeof (p_nxge_dma_common_t) * ndmas, KM_SLEEP);

	dma_cntl_poolp = (p_nxge_dma_pool_t)
				KMEM_ZALLOC(sizeof (nxge_dma_pool_t), KM_SLEEP);
	dma_cntl_p = (p_nxge_dma_common_t *)KMEM_ZALLOC(
			sizeof (p_nxge_dma_common_t) * ndmas, KM_SLEEP);

	num_chunks = (uint32_t *)KMEM_ZALLOC(
			sizeof (uint32_t) * ndmas, KM_SLEEP);

	/*
	 * Assume that each DMA channel will be configured with default
	 * block size.
	 * rbr block counts are mod of batch count (16).
	 */
	nxge_port_rbr_size = p_all_cfgp->rbr_size;
	nxge_port_rcr_size = p_all_cfgp->rcr_size;

	if (!nxge_port_rbr_size) {
		nxge_port_rbr_size = NXGE_RBR_RBB_DEFAULT;
	}
	if (nxge_port_rbr_size % NXGE_RXDMA_POST_BATCH) {
		nxge_port_rbr_size = (NXGE_RXDMA_POST_BATCH *
			(nxge_port_rbr_size / NXGE_RXDMA_POST_BATCH + 1));
	}

	p_all_cfgp->rbr_size = nxge_port_rbr_size;
	nxge_port_rbr_spare_size = nxge_rbr_spare_size;

	if (nxge_port_rbr_spare_size % NXGE_RXDMA_POST_BATCH) {
		nxge_port_rbr_spare_size = (NXGE_RXDMA_POST_BATCH *
			(nxge_port_rbr_spare_size / NXGE_RXDMA_POST_BATCH + 1));
	}
	if (nxge_port_rbr_size > RBR_DEFAULT_MAX_BLKS) {
		NXGE_DEBUG_MSG((nxgep, MEM_CTL,
		    "nxge_alloc_rx_mem_pool: RBR size too high %d, "
		    "set to default %d",
		    nxge_port_rbr_size, RBR_DEFAULT_MAX_BLKS));
		nxge_port_rbr_size = RBR_DEFAULT_MAX_BLKS;
	}
	if (nxge_port_rcr_size > RCR_DEFAULT_MAX) {
		NXGE_DEBUG_MSG((nxgep, MEM_CTL,
		    "nxge_alloc_rx_mem_pool: RCR too high %d, "
		    "set to default %d",
		    nxge_port_rcr_size, RCR_DEFAULT_MAX));
		nxge_port_rcr_size = RCR_DEFAULT_MAX;
	}

	/*
	 * N2/NIU has limitation on the descriptor sizes (contiguous
	 * memory allocation on data buffers to 4M (contig_mem_alloc)
	 * and little endian for control buffers (must use the ddi/dki mem alloc
	 * function).
	 */
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	if (nxgep->niu_type == N2_NIU) {
		nxge_port_rbr_spare_size = 0;
		if ((nxge_port_rbr_size > NXGE_NIU_CONTIG_RBR_MAX) ||
				(!ISP2(nxge_port_rbr_size))) {
			nxge_port_rbr_size = NXGE_NIU_CONTIG_RBR_MAX;
		}
		if ((nxge_port_rcr_size > NXGE_NIU_CONTIG_RCR_MAX) ||
				(!ISP2(nxge_port_rcr_size))) {
			nxge_port_rcr_size = NXGE_NIU_CONTIG_RCR_MAX;
		}
	}
#endif

	rx_buf_alloc_size = (nxgep->rx_default_block_size *
		(nxge_port_rbr_size + nxge_port_rbr_spare_size));

	/*
	 * Addresses of receive block ring, receive completion ring and the
	 * mailbox must be all cache-aligned (64 bytes).
	 */
	rx_cntl_alloc_size = nxge_port_rbr_size + nxge_port_rbr_spare_size;
	rx_cntl_alloc_size *= (sizeof (rx_desc_t));
	rx_cntl_alloc_size += (sizeof (rcr_entry_t) * nxge_port_rcr_size);
	rx_cntl_alloc_size += sizeof (rxdma_mailbox_t);

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "==> nxge_alloc_rx_mem_pool: "
		"nxge_port_rbr_size = %d nxge_port_rbr_spare_size = %d "
		"nxge_port_rcr_size = %d "
		"rx_cntl_alloc_size = %d",
		nxge_port_rbr_size, nxge_port_rbr_spare_size,
		nxge_port_rcr_size,
		rx_cntl_alloc_size));

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	if (nxgep->niu_type == N2_NIU) {
		if (!ISP2(rx_buf_alloc_size)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_alloc_rx_mem_pool: "
				" must be power of 2"));
			status |= (NXGE_ERROR | NXGE_DDI_FAILED);
			goto nxge_alloc_rx_mem_pool_exit;
		}

		if (rx_buf_alloc_size > (1 << 22)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_alloc_rx_mem_pool: "
				" limit size to 4M"));
			status |= (NXGE_ERROR | NXGE_DDI_FAILED);
			goto nxge_alloc_rx_mem_pool_exit;
		}

		if (rx_cntl_alloc_size < 0x2000) {
			rx_cntl_alloc_size = 0x2000;
		}
	}
#endif
	nxgep->nxge_port_rbr_size = nxge_port_rbr_size;
	nxgep->nxge_port_rcr_size = nxge_port_rcr_size;

	/*
	 * Allocate memory for receive buffers and descriptor rings.
	 * Replace allocation functions with interface functions provided
	 * by the partition manager when it is available.
	 */
	/*
	 * Allocate memory for the receive buffer blocks.
	 */
	for (i = 0; i < ndmas; i++) {
		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
			" nxge_alloc_rx_mem_pool to alloc mem: "
			" dma %d dma_buf_p %llx &dma_buf_p %llx",
			i, dma_buf_p[i], &dma_buf_p[i]));
		num_chunks[i] = 0;
		status = nxge_alloc_rx_buf_dma(nxgep, st_rdc, &dma_buf_p[i],
				rx_buf_alloc_size,
				nxgep->rx_default_block_size, &num_chunks[i]);
		if (status != NXGE_OK) {
			break;
		}
		st_rdc++;
		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
			" nxge_alloc_rx_mem_pool DONE  alloc mem: "
			"dma %d dma_buf_p %llx &dma_buf_p %llx", i,
			dma_buf_p[i], &dma_buf_p[i]));
	}
	if (i < ndmas) {
		goto nxge_alloc_rx_mem_fail1;
	}
	/*
	 * Allocate memory for descriptor rings and mailbox.
	 */
	st_rdc = p_cfgp->start_rdc;
	for (j = 0; j < ndmas; j++) {
		status = nxge_alloc_rx_cntl_dma(nxgep, st_rdc, &dma_cntl_p[j],
					rx_cntl_alloc_size);
		if (status != NXGE_OK) {
			break;
		}
		st_rdc++;
	}
	if (j < ndmas) {
		goto nxge_alloc_rx_mem_fail2;
	}

	dma_poolp->ndmas = ndmas;
	dma_poolp->num_chunks = num_chunks;
	dma_poolp->buf_allocated = B_TRUE;
	nxgep->rx_buf_pool_p = dma_poolp;
	dma_poolp->dma_buf_pool_p = dma_buf_p;

	dma_cntl_poolp->ndmas = ndmas;
	dma_cntl_poolp->buf_allocated = B_TRUE;
	nxgep->rx_cntl_pool_p = dma_cntl_poolp;
	dma_cntl_poolp->dma_buf_pool_p = dma_cntl_p;

	goto nxge_alloc_rx_mem_pool_exit;

nxge_alloc_rx_mem_fail2:
	/* Free control buffers */
	j--;
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_alloc_rx_mem_pool: freeing control bufs (%d)", j));
	for (; j >= 0; j--) {
		nxge_free_rx_cntl_dma(nxgep,
			(p_nxge_dma_common_t)dma_cntl_p[j]);
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
			"==> nxge_alloc_rx_mem_pool: control bufs freed (%d)",
			j));
	}
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_alloc_rx_mem_pool: control bufs freed (%d)", j));

nxge_alloc_rx_mem_fail1:
	/* Free data buffers */
	i--;
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_alloc_rx_mem_pool: freeing data bufs (%d)", i));
	for (; i >= 0; i--) {
		nxge_free_rx_buf_dma(nxgep, (p_nxge_dma_common_t)dma_buf_p[i],
			num_chunks[i]);
	}
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_alloc_rx_mem_pool: data bufs freed (%d)", i));

	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);
	KMEM_FREE(dma_poolp, sizeof (nxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(dma_cntl_poolp, sizeof (nxge_dma_pool_t));
	KMEM_FREE(dma_cntl_p, ndmas * sizeof (p_nxge_dma_common_t));

nxge_alloc_rx_mem_pool_exit:
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"<== nxge_alloc_rx_mem_pool:status 0x%08x", status));

	return (status);
}

static void
nxge_free_rx_mem_pool(p_nxge_t nxgep)
{
	uint32_t		i, ndmas;
	p_nxge_dma_pool_t	dma_poolp;
	p_nxge_dma_common_t	*dma_buf_p;
	p_nxge_dma_pool_t	dma_cntl_poolp;
	p_nxge_dma_common_t	*dma_cntl_p;
	uint32_t 		*num_chunks;

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "==> nxge_free_rx_mem_pool"));

	dma_poolp = nxgep->rx_buf_pool_p;
	if (dma_poolp == NULL || (!dma_poolp->buf_allocated)) {
		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
			"<== nxge_free_rx_mem_pool "
			"(null rx buf pool or buf not allocated"));
		return;
	}

	dma_cntl_poolp = nxgep->rx_cntl_pool_p;
	if (dma_cntl_poolp == NULL || (!dma_cntl_poolp->buf_allocated)) {
		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
			"<== nxge_free_rx_mem_pool "
			"(null rx cntl buf pool or cntl buf not allocated"));
		return;
	}

	dma_buf_p = dma_poolp->dma_buf_pool_p;
	num_chunks = dma_poolp->num_chunks;

	dma_cntl_p = dma_cntl_poolp->dma_buf_pool_p;
	ndmas = dma_cntl_poolp->ndmas;

	for (i = 0; i < ndmas; i++) {
		nxge_free_rx_buf_dma(nxgep, dma_buf_p[i], num_chunks[i]);
	}

	for (i = 0; i < ndmas; i++) {
		nxge_free_rx_cntl_dma(nxgep, dma_cntl_p[i]);
	}

	for (i = 0; i < ndmas; i++) {
		KMEM_FREE(dma_buf_p[i],
			sizeof (nxge_dma_common_t) * NXGE_DMA_BLOCK);
		KMEM_FREE(dma_cntl_p[i], sizeof (nxge_dma_common_t));
	}

	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);
	KMEM_FREE(dma_cntl_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(dma_cntl_poolp, sizeof (nxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(dma_poolp, sizeof (nxge_dma_pool_t));

	nxgep->rx_buf_pool_p = NULL;
	nxgep->rx_cntl_pool_p = NULL;

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "<== nxge_free_rx_mem_pool"));
}


static nxge_status_t
nxge_alloc_rx_buf_dma(p_nxge_t nxgep, uint16_t dma_channel,
	p_nxge_dma_common_t *dmap,
	size_t alloc_size, size_t block_size, uint32_t *num_chunks)
{
	p_nxge_dma_common_t 	rx_dmap;
	nxge_status_t		status = NXGE_OK;
	size_t			total_alloc_size;
	size_t			allocated = 0;
	int			i, size_index, array_size;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_alloc_rx_buf_dma"));

	rx_dmap = (p_nxge_dma_common_t)
			KMEM_ZALLOC(sizeof (nxge_dma_common_t) * NXGE_DMA_BLOCK,
			KM_SLEEP);

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
		" alloc_rx_buf_dma rdc %d asize %x bsize %x bbuf %llx ",
		dma_channel, alloc_size, block_size, dmap));

	total_alloc_size = alloc_size;

#if defined(RX_USE_RECLAIM_POST)
	total_alloc_size = alloc_size + alloc_size/4;
#endif

	i = 0;
	size_index = 0;
	array_size =  sizeof (alloc_sizes)/sizeof (size_t);
	while ((alloc_sizes[size_index] < alloc_size) &&
			(size_index < array_size))
			size_index++;
	if (size_index >= array_size) {
		size_index = array_size - 1;
	}

	while ((allocated < total_alloc_size) &&
			(size_index >= 0) && (i < NXGE_DMA_BLOCK)) {
		rx_dmap[i].dma_chunk_index = i;
		rx_dmap[i].block_size = block_size;
		rx_dmap[i].alength = alloc_sizes[size_index];
		rx_dmap[i].orig_alength = rx_dmap[i].alength;
		rx_dmap[i].nblocks = alloc_sizes[size_index] / block_size;
		rx_dmap[i].dma_channel = dma_channel;
		rx_dmap[i].contig_alloc_type = B_FALSE;

		/*
		 * N2/NIU: data buffers must be contiguous as the driver
		 *	   needs to call Hypervisor api to set up
		 *	   logical pages.
		 */
		if ((nxgep->niu_type == N2_NIU) && (NXGE_DMA_BLOCK == 1)) {
			rx_dmap[i].contig_alloc_type = B_TRUE;
		}

		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
			"alloc_rx_buf_dma rdc %d chunk %d bufp %llx size %x "
			"i %d nblocks %d alength %d",
			dma_channel, i, &rx_dmap[i], block_size,
			i, rx_dmap[i].nblocks,
			rx_dmap[i].alength));
		status = nxge_dma_mem_alloc(nxgep, nxge_force_dma,
			&nxge_rx_dma_attr,
			rx_dmap[i].alength,
			&nxge_dev_buf_dma_acc_attr,
			DDI_DMA_READ | DDI_DMA_STREAMING,
			(p_nxge_dma_common_t)(&rx_dmap[i]));
		if (status != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				" nxge_alloc_rx_buf_dma: Alloc Failed "));
			size_index--;
		} else {
			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
				" alloc_rx_buf_dma allocated rdc %d "
				"chunk %d size %x dvma %x bufp %llx ",
				dma_channel, i, rx_dmap[i].alength,
				rx_dmap[i].ioaddr_pp, &rx_dmap[i]));
			i++;
			allocated += alloc_sizes[size_index];
		}
	}


	if (allocated < total_alloc_size) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_alloc_rx_buf_dma: not enough for channe %d "
		    "allocated 0x%x requested 0x%x",
		    dma_channel,
		    allocated, total_alloc_size));
		status = NXGE_ERROR;
		goto nxge_alloc_rx_mem_fail1;
	}

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
	    "==> nxge_alloc_rx_buf_dma: Allocated for channe %d "
	    "allocated 0x%x requested 0x%x",
	    dma_channel,
	    allocated, total_alloc_size));

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		" alloc_rx_buf_dma rdc %d allocated %d chunks",
		dma_channel, i));
	*num_chunks = i;
	*dmap = rx_dmap;

	goto nxge_alloc_rx_mem_exit;

nxge_alloc_rx_mem_fail1:
	KMEM_FREE(rx_dmap, sizeof (nxge_dma_common_t) * NXGE_DMA_BLOCK);

nxge_alloc_rx_mem_exit:
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"<== nxge_alloc_rx_buf_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
nxge_free_rx_buf_dma(p_nxge_t nxgep, p_nxge_dma_common_t dmap,
    uint32_t num_chunks)
{
	int		i;

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
		"==> nxge_free_rx_buf_dma: # of chunks %d", num_chunks));

	for (i = 0; i < num_chunks; i++) {
		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
			"==> nxge_free_rx_buf_dma: chunk %d dmap 0x%llx",
				i, dmap));
		nxge_dma_mem_free(dmap++);
	}

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "==> nxge_free_rx_buf_dma"));
}

/*ARGSUSED*/
static nxge_status_t
nxge_alloc_rx_cntl_dma(p_nxge_t nxgep, uint16_t dma_channel,
    p_nxge_dma_common_t *dmap, size_t size)
{
	p_nxge_dma_common_t 	rx_dmap;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_alloc_rx_cntl_dma"));

	rx_dmap = (p_nxge_dma_common_t)
			KMEM_ZALLOC(sizeof (nxge_dma_common_t), KM_SLEEP);

	rx_dmap->contig_alloc_type = B_FALSE;

	status = nxge_dma_mem_alloc(nxgep, nxge_force_dma,
			&nxge_desc_dma_attr,
			size,
			&nxge_dev_desc_dma_acc_attr,
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			rx_dmap);
	if (status != NXGE_OK) {
		goto nxge_alloc_rx_cntl_dma_fail1;
	}

	*dmap = rx_dmap;
	goto nxge_alloc_rx_cntl_dma_exit;

nxge_alloc_rx_cntl_dma_fail1:
	KMEM_FREE(rx_dmap, sizeof (nxge_dma_common_t));

nxge_alloc_rx_cntl_dma_exit:
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"<== nxge_alloc_rx_cntl_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
nxge_free_rx_cntl_dma(p_nxge_t nxgep, p_nxge_dma_common_t dmap)
{
	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_free_rx_cntl_dma"));

	nxge_dma_mem_free(dmap);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_free_rx_cntl_dma"));
}

static nxge_status_t
nxge_alloc_tx_mem_pool(p_nxge_t nxgep)
{
	nxge_status_t		status = NXGE_OK;
	int			i, j;
	uint32_t		ndmas, st_tdc;
	p_nxge_dma_pt_cfg_t	p_all_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	p_nxge_dma_pool_t	dma_poolp;
	p_nxge_dma_common_t	*dma_buf_p;
	p_nxge_dma_pool_t	dma_cntl_poolp;
	p_nxge_dma_common_t	*dma_cntl_p;
	size_t			tx_buf_alloc_size;
	size_t			tx_cntl_alloc_size;
	uint32_t		*num_chunks; /* per dma */
	uint32_t		bcopy_thresh;

	NXGE_DEBUG_MSG((nxgep, MEM_CTL, "==> nxge_alloc_tx_mem_pool"));

	p_all_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;
	st_tdc = p_cfgp->start_tdc;
	ndmas = p_cfgp->max_tdcs;

	NXGE_DEBUG_MSG((nxgep, MEM_CTL, "==> nxge_alloc_tx_mem_pool: "
		"p_cfgp 0x%016llx start_tdc %d ndmas %d nxgep->max_tdcs %d",
		p_cfgp, p_cfgp->start_tdc, p_cfgp->max_tdcs, nxgep->max_tdcs));
	/*
	 * Allocate memory for each transmit DMA channel.
	 */
	dma_poolp = (p_nxge_dma_pool_t)KMEM_ZALLOC(sizeof (nxge_dma_pool_t),
			KM_SLEEP);
	dma_buf_p = (p_nxge_dma_common_t *)KMEM_ZALLOC(
			sizeof (p_nxge_dma_common_t) * ndmas, KM_SLEEP);

	dma_cntl_poolp = (p_nxge_dma_pool_t)
			KMEM_ZALLOC(sizeof (nxge_dma_pool_t), KM_SLEEP);
	dma_cntl_p = (p_nxge_dma_common_t *)KMEM_ZALLOC(
			sizeof (p_nxge_dma_common_t) * ndmas, KM_SLEEP);

	if (nxge_tx_ring_size > TDC_DEFAULT_MAX) {
		NXGE_DEBUG_MSG((nxgep, MEM_CTL,
		    "nxge_alloc_tx_mem_pool: TDC too high %d, "
		    "set to default %d",
		    nxge_tx_ring_size, TDC_DEFAULT_MAX));
		nxge_tx_ring_size = TDC_DEFAULT_MAX;
	}

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	/*
	 * N2/NIU has limitation on the descriptor sizes (contiguous
	 * memory allocation on data buffers to 4M (contig_mem_alloc)
	 * and little endian for control buffers (must use the ddi/dki mem alloc
	 * function). The transmit ring is limited to 8K (includes the
	 * mailbox).
	 */
	if (nxgep->niu_type == N2_NIU) {
		if ((nxge_tx_ring_size > NXGE_NIU_CONTIG_TX_MAX) ||
			(!ISP2(nxge_tx_ring_size))) {
			nxge_tx_ring_size = NXGE_NIU_CONTIG_TX_MAX;
		}
	}
#endif

	nxgep->nxge_port_tx_ring_size = nxge_tx_ring_size;

	/*
	 * Assume that each DMA channel will be configured with default
	 * transmit bufer size for copying transmit data.
	 * (For packet payload over this limit, packets will not be
	 *  copied.)
	 */
	if (nxgep->niu_type == N2_NIU) {
		bcopy_thresh = TX_BCOPY_SIZE;
	} else {
		bcopy_thresh = nxge_bcopy_thresh;
	}
	tx_buf_alloc_size = (bcopy_thresh * nxge_tx_ring_size);

	/*
	 * Addresses of transmit descriptor ring and the
	 * mailbox must be all cache-aligned (64 bytes).
	 */
	tx_cntl_alloc_size = nxge_tx_ring_size;
	tx_cntl_alloc_size *= (sizeof (tx_desc_t));
	tx_cntl_alloc_size += sizeof (txdma_mailbox_t);

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	if (nxgep->niu_type == N2_NIU) {
		if (!ISP2(tx_buf_alloc_size)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_alloc_tx_mem_pool: "
				" must be power of 2"));
			status |= (NXGE_ERROR | NXGE_DDI_FAILED);
			goto nxge_alloc_tx_mem_pool_exit;
		}

		if (tx_buf_alloc_size > (1 << 22)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_alloc_tx_mem_pool: "
				" limit size to 4M"));
			status |= (NXGE_ERROR | NXGE_DDI_FAILED);
			goto nxge_alloc_tx_mem_pool_exit;
		}

		if (tx_cntl_alloc_size < 0x2000) {
			tx_cntl_alloc_size = 0x2000;
		}
	}
#endif

	num_chunks = (uint32_t *)KMEM_ZALLOC(
			sizeof (uint32_t) * ndmas, KM_SLEEP);

	/*
	 * Allocate memory for transmit buffers and descriptor rings.
	 * Replace allocation functions with interface functions provided
	 * by the partition manager when it is available.
	 *
	 * Allocate memory for the transmit buffer pool.
	 */
	for (i = 0; i < ndmas; i++) {
		num_chunks[i] = 0;
		status = nxge_alloc_tx_buf_dma(nxgep, st_tdc, &dma_buf_p[i],
					tx_buf_alloc_size,
					bcopy_thresh, &num_chunks[i]);
		if (status != NXGE_OK) {
			break;
		}
		st_tdc++;
	}
	if (i < ndmas) {
		goto nxge_alloc_tx_mem_pool_fail1;
	}

	st_tdc = p_cfgp->start_tdc;
	/*
	 * Allocate memory for descriptor rings and mailbox.
	 */
	for (j = 0; j < ndmas; j++) {
		status = nxge_alloc_tx_cntl_dma(nxgep, st_tdc, &dma_cntl_p[j],
					tx_cntl_alloc_size);
		if (status != NXGE_OK) {
			break;
		}
		st_tdc++;
	}
	if (j < ndmas) {
		goto nxge_alloc_tx_mem_pool_fail2;
	}

	dma_poolp->ndmas = ndmas;
	dma_poolp->num_chunks = num_chunks;
	dma_poolp->buf_allocated = B_TRUE;
	dma_poolp->dma_buf_pool_p = dma_buf_p;
	nxgep->tx_buf_pool_p = dma_poolp;

	dma_cntl_poolp->ndmas = ndmas;
	dma_cntl_poolp->buf_allocated = B_TRUE;
	dma_cntl_poolp->dma_buf_pool_p = dma_cntl_p;
	nxgep->tx_cntl_pool_p = dma_cntl_poolp;

	NXGE_DEBUG_MSG((nxgep, MEM_CTL,
		"==> nxge_alloc_tx_mem_pool: start_tdc %d "
		"ndmas %d poolp->ndmas %d",
		st_tdc, ndmas, dma_poolp->ndmas));

	goto nxge_alloc_tx_mem_pool_exit;

nxge_alloc_tx_mem_pool_fail2:
	/* Free control buffers */
	j--;
	for (; j >= 0; j--) {
		nxge_free_tx_cntl_dma(nxgep,
			(p_nxge_dma_common_t)dma_cntl_p[j]);
	}

nxge_alloc_tx_mem_pool_fail1:
	/* Free data buffers */
	i--;
	for (; i >= 0; i--) {
		nxge_free_tx_buf_dma(nxgep, (p_nxge_dma_common_t)dma_buf_p[i],
			num_chunks[i]);
	}

	KMEM_FREE(dma_poolp, sizeof (nxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(dma_cntl_poolp, sizeof (nxge_dma_pool_t));
	KMEM_FREE(dma_cntl_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);

nxge_alloc_tx_mem_pool_exit:
	NXGE_DEBUG_MSG((nxgep, MEM_CTL,
		"<== nxge_alloc_tx_mem_pool:status 0x%08x", status));

	return (status);
}

static nxge_status_t
nxge_alloc_tx_buf_dma(p_nxge_t nxgep, uint16_t dma_channel,
    p_nxge_dma_common_t *dmap, size_t alloc_size,
    size_t block_size, uint32_t *num_chunks)
{
	p_nxge_dma_common_t 	tx_dmap;
	nxge_status_t		status = NXGE_OK;
	size_t			total_alloc_size;
	size_t			allocated = 0;
	int			i, size_index, array_size;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_alloc_tx_buf_dma"));

	tx_dmap = (p_nxge_dma_common_t)
		KMEM_ZALLOC(sizeof (nxge_dma_common_t) * NXGE_DMA_BLOCK,
			KM_SLEEP);

	total_alloc_size = alloc_size;
	i = 0;
	size_index = 0;
	array_size =  sizeof (alloc_sizes) /  sizeof (size_t);
	while ((alloc_sizes[size_index] < alloc_size) &&
		(size_index < array_size))
		size_index++;
	if (size_index >= array_size) {
		size_index = array_size - 1;
	}

	while ((allocated < total_alloc_size) &&
			(size_index >= 0) && (i < NXGE_DMA_BLOCK)) {

		tx_dmap[i].dma_chunk_index = i;
		tx_dmap[i].block_size = block_size;
		tx_dmap[i].alength = alloc_sizes[size_index];
		tx_dmap[i].orig_alength = tx_dmap[i].alength;
		tx_dmap[i].nblocks = alloc_sizes[size_index] / block_size;
		tx_dmap[i].dma_channel = dma_channel;
		tx_dmap[i].contig_alloc_type = B_FALSE;

		/*
		 * N2/NIU: data buffers must be contiguous as the driver
		 *	   needs to call Hypervisor api to set up
		 *	   logical pages.
		 */
		if ((nxgep->niu_type == N2_NIU) && (NXGE_DMA_BLOCK == 1)) {
			tx_dmap[i].contig_alloc_type = B_TRUE;
		}

		status = nxge_dma_mem_alloc(nxgep, nxge_force_dma,
			&nxge_tx_dma_attr,
			tx_dmap[i].alength,
			&nxge_dev_buf_dma_acc_attr,
			DDI_DMA_WRITE | DDI_DMA_STREAMING,
			(p_nxge_dma_common_t)(&tx_dmap[i]));
		if (status != NXGE_OK) {
			size_index--;
		} else {
			i++;
			allocated += alloc_sizes[size_index];
		}
	}

	if (allocated < total_alloc_size) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_alloc_tx_buf_dma: not enough channel %d: "
		    "allocated 0x%x requested 0x%x",
		    dma_channel,
		    allocated, total_alloc_size));
		status = NXGE_ERROR;
		goto nxge_alloc_tx_mem_fail1;
	}

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
	    "==> nxge_alloc_tx_buf_dma: Allocated for channel %d: "
	    "allocated 0x%x requested 0x%x",
	    dma_channel,
	    allocated, total_alloc_size));

	*num_chunks = i;
	*dmap = tx_dmap;
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_alloc_tx_buf_dma dmap 0x%016llx num chunks %d",
		*dmap, i));
	goto nxge_alloc_tx_mem_exit;

nxge_alloc_tx_mem_fail1:
	KMEM_FREE(tx_dmap, sizeof (nxge_dma_common_t) * NXGE_DMA_BLOCK);

nxge_alloc_tx_mem_exit:
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"<== nxge_alloc_tx_buf_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
nxge_free_tx_buf_dma(p_nxge_t nxgep, p_nxge_dma_common_t dmap,
    uint32_t num_chunks)
{
	int		i;

	NXGE_DEBUG_MSG((nxgep, MEM_CTL, "==> nxge_free_tx_buf_dma"));

	for (i = 0; i < num_chunks; i++) {
		nxge_dma_mem_free(dmap++);
	}

	NXGE_DEBUG_MSG((nxgep, MEM_CTL, "<== nxge_free_tx_buf_dma"));
}

/*ARGSUSED*/
static nxge_status_t
nxge_alloc_tx_cntl_dma(p_nxge_t nxgep, uint16_t dma_channel,
    p_nxge_dma_common_t *dmap, size_t size)
{
	p_nxge_dma_common_t 	tx_dmap;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_alloc_tx_cntl_dma"));
	tx_dmap = (p_nxge_dma_common_t)
			KMEM_ZALLOC(sizeof (nxge_dma_common_t), KM_SLEEP);

	tx_dmap->contig_alloc_type = B_FALSE;

	status = nxge_dma_mem_alloc(nxgep, nxge_force_dma,
			&nxge_desc_dma_attr,
			size,
			&nxge_dev_desc_dma_acc_attr,
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			tx_dmap);
	if (status != NXGE_OK) {
		goto nxge_alloc_tx_cntl_dma_fail1;
	}

	*dmap = tx_dmap;
	goto nxge_alloc_tx_cntl_dma_exit;

nxge_alloc_tx_cntl_dma_fail1:
	KMEM_FREE(tx_dmap, sizeof (nxge_dma_common_t));

nxge_alloc_tx_cntl_dma_exit:
	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"<== nxge_alloc_tx_cntl_dma status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
nxge_free_tx_cntl_dma(p_nxge_t nxgep, p_nxge_dma_common_t dmap)
{
	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_free_tx_cntl_dma"));

	nxge_dma_mem_free(dmap);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_free_tx_cntl_dma"));
}

static void
nxge_free_tx_mem_pool(p_nxge_t nxgep)
{
	uint32_t		i, ndmas;
	p_nxge_dma_pool_t	dma_poolp;
	p_nxge_dma_common_t	*dma_buf_p;
	p_nxge_dma_pool_t	dma_cntl_poolp;
	p_nxge_dma_common_t	*dma_cntl_p;
	uint32_t 		*num_chunks;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_free_tx_mem_pool"));

	dma_poolp = nxgep->tx_buf_pool_p;
	if (dma_poolp == NULL || (!dma_poolp->buf_allocated)) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_free_tx_mem_pool "
			"(null rx buf pool or buf not allocated"));
		return;
	}

	dma_cntl_poolp = nxgep->tx_cntl_pool_p;
	if (dma_cntl_poolp == NULL || (!dma_cntl_poolp->buf_allocated)) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_free_tx_mem_pool "
			"(null tx cntl buf pool or cntl buf not allocated"));
		return;
	}

	dma_buf_p = dma_poolp->dma_buf_pool_p;
	num_chunks = dma_poolp->num_chunks;

	dma_cntl_p = dma_cntl_poolp->dma_buf_pool_p;
	ndmas = dma_cntl_poolp->ndmas;

	for (i = 0; i < ndmas; i++) {
		nxge_free_tx_buf_dma(nxgep, dma_buf_p[i], num_chunks[i]);
	}

	for (i = 0; i < ndmas; i++) {
		nxge_free_tx_cntl_dma(nxgep, dma_cntl_p[i]);
	}

	for (i = 0; i < ndmas; i++) {
		KMEM_FREE(dma_buf_p[i],
			sizeof (nxge_dma_common_t) * NXGE_DMA_BLOCK);
		KMEM_FREE(dma_cntl_p[i], sizeof (nxge_dma_common_t));
	}

	KMEM_FREE(num_chunks, sizeof (uint32_t) * ndmas);
	KMEM_FREE(dma_cntl_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(dma_cntl_poolp, sizeof (nxge_dma_pool_t));
	KMEM_FREE(dma_buf_p, ndmas * sizeof (p_nxge_dma_common_t));
	KMEM_FREE(dma_poolp, sizeof (nxge_dma_pool_t));

	nxgep->tx_buf_pool_p = NULL;
	nxgep->tx_cntl_pool_p = NULL;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_free_tx_mem_pool"));
}

/*ARGSUSED*/
static nxge_status_t
nxge_dma_mem_alloc(p_nxge_t nxgep, dma_method_t method,
	struct ddi_dma_attr *dma_attrp,
	size_t length, ddi_device_acc_attr_t *acc_attr_p, uint_t xfer_flags,
	p_nxge_dma_common_t dma_p)
{
	caddr_t 		kaddrp;
	int			ddi_status = DDI_SUCCESS;
	boolean_t		contig_alloc_type;

	contig_alloc_type = dma_p->contig_alloc_type;

	if (contig_alloc_type && (nxgep->niu_type != N2_NIU)) {
		/*
		 * contig_alloc_type for contiguous memory only allowed
		 * for N2/NIU.
		 */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_dma_mem_alloc: alloc type not allows (%d)",
			dma_p->contig_alloc_type));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	dma_p->dma_handle = NULL;
	dma_p->acc_handle = NULL;
	dma_p->kaddrp = dma_p->last_kaddrp = NULL;
	dma_p->first_ioaddr_pp = dma_p->last_ioaddr_pp = NULL;
	ddi_status = ddi_dma_alloc_handle(nxgep->dip, dma_attrp,
		DDI_DMA_DONTWAIT, NULL, &dma_p->dma_handle);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_dma_mem_alloc:ddi_dma_alloc_handle failed."));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	switch (contig_alloc_type) {
	case B_FALSE:
		ddi_status = ddi_dma_mem_alloc(dma_p->dma_handle, length,
			acc_attr_p,
			xfer_flags,
			DDI_DMA_DONTWAIT, 0, &kaddrp, &dma_p->alength,
			&dma_p->acc_handle);
		if (ddi_status != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_dma_mem_alloc:ddi_dma_mem_alloc failed"));
			ddi_dma_free_handle(&dma_p->dma_handle);
			dma_p->dma_handle = NULL;
			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}
		if (dma_p->alength < length) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_dma_mem_alloc:ddi_dma_mem_alloc "
				"< length."));
			ddi_dma_mem_free(&dma_p->acc_handle);
			ddi_dma_free_handle(&dma_p->dma_handle);
			dma_p->acc_handle = NULL;
			dma_p->dma_handle = NULL;
			return (NXGE_ERROR);
		}

		ddi_status = ddi_dma_addr_bind_handle(dma_p->dma_handle, NULL,
			kaddrp, dma_p->alength, xfer_flags, DDI_DMA_DONTWAIT, 0,
			&dma_p->dma_cookie, &dma_p->ncookies);
		if (ddi_status != DDI_DMA_MAPPED) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_dma_mem_alloc:di_dma_addr_bind failed "
				"(staus 0x%x ncookies %d.)", ddi_status,
				dma_p->ncookies));
			if (dma_p->acc_handle) {
				ddi_dma_mem_free(&dma_p->acc_handle);
				dma_p->acc_handle = NULL;
			}
			ddi_dma_free_handle(&dma_p->dma_handle);
			dma_p->dma_handle = NULL;
			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}

		if (dma_p->ncookies != 1) {
			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
				"nxge_dma_mem_alloc:ddi_dma_addr_bind "
				"> 1 cookie"
				"(staus 0x%x ncookies %d.)", ddi_status,
				dma_p->ncookies));
			if (dma_p->acc_handle) {
				ddi_dma_mem_free(&dma_p->acc_handle);
				dma_p->acc_handle = NULL;
			}
			(void) ddi_dma_unbind_handle(dma_p->dma_handle);
			ddi_dma_free_handle(&dma_p->dma_handle);
			dma_p->dma_handle = NULL;
			return (NXGE_ERROR);
		}
		break;

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	case B_TRUE:
		kaddrp = (caddr_t)contig_mem_alloc(length);
		if (kaddrp == NULL) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_dma_mem_alloc:contig_mem_alloc failed."));
			ddi_dma_free_handle(&dma_p->dma_handle);
			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}

		dma_p->alength = length;
		ddi_status = ddi_dma_addr_bind_handle(dma_p->dma_handle, NULL,
			kaddrp, dma_p->alength, xfer_flags, DDI_DMA_DONTWAIT, 0,
			&dma_p->dma_cookie, &dma_p->ncookies);
		if (ddi_status != DDI_DMA_MAPPED) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_dma_mem_alloc:di_dma_addr_bind failed "
				"(status 0x%x ncookies %d.)", ddi_status,
				dma_p->ncookies));

			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
				"==> nxge_dma_mem_alloc: (not mapped)"
				"length %lu (0x%x) "
				"free contig kaddrp $%p "
				"va_to_pa $%p",
				length, length,
				kaddrp,
				va_to_pa(kaddrp)));


			contig_mem_free((void *)kaddrp, length);
			ddi_dma_free_handle(&dma_p->dma_handle);

			dma_p->dma_handle = NULL;
			dma_p->acc_handle = NULL;
			dma_p->alength = NULL;
			dma_p->kaddrp = NULL;

			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}

		if (dma_p->ncookies != 1 ||
			(dma_p->dma_cookie.dmac_laddress == NULL)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_dma_mem_alloc:di_dma_addr_bind > 1 "
				"cookie or "
				"dmac_laddress is NULL $%p size %d "
				" (status 0x%x ncookies %d.)",
				ddi_status,
				dma_p->dma_cookie.dmac_laddress,
				dma_p->dma_cookie.dmac_size,
				dma_p->ncookies));

			contig_mem_free((void *)kaddrp, length);
			(void) ddi_dma_unbind_handle(dma_p->dma_handle);
			ddi_dma_free_handle(&dma_p->dma_handle);

			dma_p->alength = 0;
			dma_p->dma_handle = NULL;
			dma_p->acc_handle = NULL;
			dma_p->kaddrp = NULL;

			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}
		break;

#else
	case B_TRUE:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_dma_mem_alloc: invalid alloc type for !sun4v"));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
#endif
	}

	dma_p->kaddrp = kaddrp;
	dma_p->last_kaddrp = (unsigned char *)kaddrp +
			dma_p->alength - RXBUF_64B_ALIGNED;
#if defined(__i386)
	dma_p->ioaddr_pp =
		(unsigned char *)(uint32_t)dma_p->dma_cookie.dmac_laddress;
#else
	dma_p->ioaddr_pp = (unsigned char *)dma_p->dma_cookie.dmac_laddress;
#endif
	dma_p->last_ioaddr_pp =
#if defined(__i386)
		(unsigned char *)(uint32_t)dma_p->dma_cookie.dmac_laddress +
#else
		(unsigned char *)dma_p->dma_cookie.dmac_laddress +
#endif
				dma_p->alength - RXBUF_64B_ALIGNED;

	NPI_DMA_ACC_HANDLE_SET(dma_p, dma_p->acc_handle);

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	dma_p->orig_ioaddr_pp =
		(unsigned char *)dma_p->dma_cookie.dmac_laddress;
	dma_p->orig_alength = length;
	dma_p->orig_kaddrp = kaddrp;
	dma_p->orig_vatopa = (uint64_t)va_to_pa(kaddrp);
#endif

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_dma_mem_alloc: "
		"dma buffer allocated: dma_p $%p "
		"return dmac_ladress from cookie $%p cookie dmac_size %d "
		"dma_p->ioaddr_p $%p "
		"dma_p->orig_ioaddr_p $%p "
		"orig_vatopa $%p "
		"alength %d (0x%x) "
		"kaddrp $%p "
		"length %d (0x%x)",
		dma_p,
		dma_p->dma_cookie.dmac_laddress, dma_p->dma_cookie.dmac_size,
		dma_p->ioaddr_pp,
		dma_p->orig_ioaddr_pp,
		dma_p->orig_vatopa,
		dma_p->alength, dma_p->alength,
		kaddrp,
		length, length));

	return (NXGE_OK);
}

static void
nxge_dma_mem_free(p_nxge_dma_common_t dma_p)
{
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
		NPI_DMA_ACC_HANDLE_SET(dma_p, NULL);
	}

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	if (dma_p->contig_alloc_type &&
			dma_p->orig_kaddrp && dma_p->orig_alength) {
		NXGE_DEBUG_MSG((NULL, DMA_CTL, "nxge_dma_mem_free: "
			"kaddrp $%p (orig_kaddrp $%p)"
			"mem type %d ",
			"orig_alength %d "
			"alength 0x%x (%d)",
			dma_p->kaddrp,
			dma_p->orig_kaddrp,
			dma_p->contig_alloc_type,
			dma_p->orig_alength,
			dma_p->alength, dma_p->alength));

		contig_mem_free(dma_p->orig_kaddrp, dma_p->orig_alength);
		dma_p->orig_alength = NULL;
		dma_p->orig_kaddrp = NULL;
		dma_p->contig_alloc_type = B_FALSE;
	}
#endif
	dma_p->kaddrp = NULL;
	dma_p->alength = NULL;
}

/*
 *	nxge_m_start() -- start transmitting and receiving.
 *
 *	This function is called by the MAC layer when the first
 *	stream is open to prepare the hardware ready for sending
 *	and transmitting packets.
 */
static int
nxge_m_start(void *arg)
{
	p_nxge_t 	nxgep = (p_nxge_t)arg;

	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "==> nxge_m_start"));

	MUTEX_ENTER(nxgep->genlock);
	if (nxge_init(nxgep) != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_m_start: initialization failed"));
		MUTEX_EXIT(nxgep->genlock);
		return (EIO);
	}

	if (nxgep->nxge_mac_state == NXGE_MAC_STARTED)
		goto nxge_m_start_exit;
	/*
	 * Start timer to check the system error and tx hangs
	 */
	nxgep->nxge_timerid = nxge_start_timer(nxgep, nxge_check_hw_state,
		NXGE_CHECK_TIMER);

	nxgep->link_notify = B_TRUE;

	nxgep->nxge_mac_state = NXGE_MAC_STARTED;

nxge_m_start_exit:
	MUTEX_EXIT(nxgep->genlock);
	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "<== nxge_m_start"));
	return (0);
}

/*
 *	nxge_m_stop(): stop transmitting and receiving.
 */
static void
nxge_m_stop(void *arg)
{
	p_nxge_t 	nxgep = (p_nxge_t)arg;

	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "==> nxge_m_stop"));

	if (nxgep->nxge_timerid) {
		nxge_stop_timer(nxgep, nxgep->nxge_timerid);
		nxgep->nxge_timerid = 0;
	}

	MUTEX_ENTER(nxgep->genlock);
	nxge_uninit(nxgep);

	nxgep->nxge_mac_state = NXGE_MAC_STOPPED;

	MUTEX_EXIT(nxgep->genlock);

	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "<== nxge_m_stop"));
}

static int
nxge_m_unicst(void *arg, const uint8_t *macaddr)
{
	p_nxge_t 	nxgep = (p_nxge_t)arg;
	struct 		ether_addr addrp;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_m_unicst"));

	bcopy(macaddr, (uint8_t *)&addrp, ETHERADDRL);
	if (nxge_set_mac_addr(nxgep, &addrp)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_m_unicst: set unitcast failed"));
		return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_m_unicst"));

	return (0);
}

static int
nxge_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	p_nxge_t 	nxgep = (p_nxge_t)arg;
	struct 		ether_addr addrp;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		"==> nxge_m_multicst: add %d", add));

	bcopy(mca, (uint8_t *)&addrp, ETHERADDRL);
	if (add) {
		if (nxge_add_mcast_addr(nxgep, &addrp)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"<== nxge_m_multicst: add multicast failed"));
			return (EINVAL);
		}
	} else {
		if (nxge_del_mcast_addr(nxgep, &addrp)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"<== nxge_m_multicst: del multicast failed"));
			return (EINVAL);
		}
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_m_multicst"));

	return (0);
}

static int
nxge_m_promisc(void *arg, boolean_t on)
{
	p_nxge_t 	nxgep = (p_nxge_t)arg;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		"==> nxge_m_promisc: on %d", on));

	if (nxge_set_promisc(nxgep, on)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_m_promisc: set promisc failed"));
		return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		"<== nxge_m_promisc: on %d", on));

	return (0);
}

static void
nxge_m_ioctl(void *arg,  queue_t *wq, mblk_t *mp)
{
	p_nxge_t 	nxgep = (p_nxge_t)arg;
	struct 		iocblk *iocp;
	boolean_t 	need_privilege;
	int 		err;
	int 		cmd;

	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "==> nxge_m_ioctl"));

	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	need_privilege = B_TRUE;
	cmd = iocp->ioc_cmd;
	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "==> nxge_m_ioctl: cmd 0x%08x", cmd));
	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "<== nxge_m_ioctl: invalid"));
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

	case NXGE_GET_MII:
	case NXGE_PUT_MII:
	case NXGE_GET64:
	case NXGE_PUT64:
	case NXGE_GET_TX_RING_SZ:
	case NXGE_GET_TX_DESC:
	case NXGE_TX_SIDE_RESET:
	case NXGE_RX_SIDE_RESET:
	case NXGE_GLOBAL_RESET:
	case NXGE_RESET_MAC:
	case NXGE_TX_REGS_DUMP:
	case NXGE_RX_REGS_DUMP:
	case NXGE_INT_REGS_DUMP:
	case NXGE_VIR_INT_REGS_DUMP:
	case NXGE_PUT_TCAM:
	case NXGE_GET_TCAM:
	case NXGE_RTRACE:
	case NXGE_RDUMP:

		need_privilege = B_FALSE;
		break;
	case NXGE_INJECT_ERR:
		cmn_err(CE_NOTE, "!nxge_m_ioctl: Inject error\n");
		nxge_err_inject(nxgep, wq, mp);
		break;
	}

	if (need_privilege) {
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"<== nxge_m_ioctl: no priv"));
			return;
		}
	}

	switch (cmd) {
	case ND_GET:
		NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "ND_GET command"));
	case ND_SET:
		NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "ND_SET command"));
		nxge_param_ioctl(nxgep, wq, mp, iocp);
		break;

	case LB_GET_MODE:
	case LB_SET_MODE:
	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
		nxge_loopback_ioctl(nxgep, wq, mp, iocp);
		break;

	case NXGE_GET_MII:
	case NXGE_PUT_MII:
	case NXGE_PUT_TCAM:
	case NXGE_GET_TCAM:
	case NXGE_GET64:
	case NXGE_PUT64:
	case NXGE_GET_TX_RING_SZ:
	case NXGE_GET_TX_DESC:
	case NXGE_TX_SIDE_RESET:
	case NXGE_RX_SIDE_RESET:
	case NXGE_GLOBAL_RESET:
	case NXGE_RESET_MAC:
	case NXGE_TX_REGS_DUMP:
	case NXGE_RX_REGS_DUMP:
	case NXGE_INT_REGS_DUMP:
	case NXGE_VIR_INT_REGS_DUMP:
		NXGE_DEBUG_MSG((nxgep, NXGE_CTL,
			"==> nxge_m_ioctl: cmd 0x%x", cmd));
		nxge_hw_ioctl(nxgep, wq, mp, iocp);
		break;
	}

	NXGE_DEBUG_MSG((nxgep, NXGE_CTL, "<== nxge_m_ioctl"));
}

extern void nxge_rx_hw_blank(void *arg, time_t ticks, uint_t count);

static void
nxge_m_resources(void *arg)
{
	p_nxge_t		nxgep = arg;
	mac_rx_fifo_t 		mrf;
	p_rx_rcr_rings_t	rcr_rings;
	p_rx_rcr_ring_t		*rcr_p;
	uint32_t		i, ndmas;
	nxge_status_t		status;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_m_resources"));

	MUTEX_ENTER(nxgep->genlock);

	/*
	 * CR 6492541 Check to see if the drv_state has been initialized,
	 * if not * call nxge_init().
	 */
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = nxge_init(nxgep);
		if (status != NXGE_OK)
			goto nxge_m_resources_exit;
	}

	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = nxge_rx_hw_blank;
	mrf.mrf_arg = (void *)nxgep;

	mrf.mrf_normal_blank_time = 128;
	mrf.mrf_normal_pkt_count = 8;
	rcr_rings = nxgep->rx_rcr_rings;
	rcr_p = rcr_rings->rcr_rings;
	ndmas = rcr_rings->ndmas;

	/*
	 * Export our receive resources to the MAC layer.
	 */
	for (i = 0; i < ndmas; i++) {
		((p_rx_rcr_ring_t)rcr_p[i])->rcr_mac_handle =
				mac_resource_add(nxgep->mach,
				    (mac_resource_t *)&mrf);

		NXGE_DEBUG_MSG((nxgep, NXGE_CTL,
			"==> nxge_m_resources: vdma %d dma %d "
			"rcrptr 0x%016llx mac_handle 0x%016llx",
			i, ((p_rx_rcr_ring_t)rcr_p[i])->rdc,
			rcr_p[i],
			((p_rx_rcr_ring_t)rcr_p[i])->rcr_mac_handle));
	}

nxge_m_resources_exit:
	MUTEX_EXIT(nxgep->genlock);
	NXGE_DEBUG_MSG((nxgep, RX_CTL, "<== nxge_m_resources"));
}

static void
nxge_mmac_kstat_update(p_nxge_t nxgep, mac_addr_slot_t slot, boolean_t factory)
{
	p_nxge_mmac_stats_t mmac_stats;
	int i;
	nxge_mmac_t *mmac_info;

	mmac_info = &nxgep->nxge_mmac_info;

	mmac_stats = &nxgep->statsp->mmac_stats;
	mmac_stats->mmac_max_cnt = mmac_info->num_mmac;
	mmac_stats->mmac_avail_cnt = mmac_info->naddrfree;

	for (i = 0; i < ETHERADDRL; i++) {
		if (factory) {
			mmac_stats->mmac_avail_pool[slot-1].ether_addr_octet[i]
			= mmac_info->factory_mac_pool[slot][(ETHERADDRL-1) - i];
		} else {
			mmac_stats->mmac_avail_pool[slot-1].ether_addr_octet[i]
			= mmac_info->mac_pool[slot].addr[(ETHERADDRL - 1) - i];
		}
	}
}

/*
 * nxge_altmac_set() -- Set an alternate MAC address
 */
static int
nxge_altmac_set(p_nxge_t nxgep, uint8_t *maddr, mac_addr_slot_t slot)
{
	uint8_t addrn;
	uint8_t portn;
	npi_mac_addr_t altmac;
	hostinfo_t mac_rdc;
	p_nxge_class_pt_cfg_t clscfgp;

	altmac.w2 = ((uint16_t)maddr[0] << 8) | ((uint16_t)maddr[1] & 0x0ff);
	altmac.w1 = ((uint16_t)maddr[2] << 8) | ((uint16_t)maddr[3] & 0x0ff);
	altmac.w0 = ((uint16_t)maddr[4] << 8) | ((uint16_t)maddr[5] & 0x0ff);

	portn = nxgep->mac.portnum;
	addrn = (uint8_t)slot - 1;

	if (npi_mac_altaddr_entry(nxgep->npi_handle, OP_SET, portn,
		addrn, &altmac) != NPI_SUCCESS)
		return (EIO);

	/*
	 * Set the rdc table number for the host info entry
	 * for this mac address slot.
	 */
	clscfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num = clscfgp->mac_host_info[addrn].rdctbl;
	mac_rdc.bits.w0.mac_pref = clscfgp->mac_host_info[addrn].mpr_npr;

	if (npi_mac_hostinfo_entry(nxgep->npi_handle, OP_SET,
	    nxgep->function_num, addrn, &mac_rdc) != NPI_SUCCESS) {
		return (EIO);
	}

	/*
	 * Enable comparison with the alternate MAC address.
	 * While the first alternate addr is enabled by bit 1 of register
	 * BMAC_ALTAD_CMPEN, it is enabled by bit 0 of register
	 * XMAC_ADDR_CMPEN, so slot needs to be converted to addrn
	 * accordingly before calling npi_mac_altaddr_entry.
	 */
	if (portn == XMAC_PORT_0 || portn == XMAC_PORT_1)
		addrn = (uint8_t)slot - 1;
	else
		addrn = (uint8_t)slot;

	if (npi_mac_altaddr_enable(nxgep->npi_handle, portn, addrn)
		!= NPI_SUCCESS)
		return (EIO);

	return (0);
}

/*
 * nxeg_m_mmac_add() - find an unused address slot, set the address
 * value to the one specified, enable the port to start filtering on
 * the new MAC address.  Returns 0 on success.
 */
static int
nxge_m_mmac_add(void *arg, mac_multi_addr_t *maddr)
{
	p_nxge_t nxgep = arg;
	mac_addr_slot_t slot;
	nxge_mmac_t *mmac_info;
	int err;
	nxge_status_t status;

	mutex_enter(nxgep->genlock);

	/*
	 * Make sure that nxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = nxge_init(nxgep);
		if (status != NXGE_OK) {
			mutex_exit(nxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &nxgep->nxge_mmac_info;
	if (mmac_info->naddrfree == 0) {
		mutex_exit(nxgep->genlock);
		return (ENOSPC);
	}
	if (!mac_unicst_verify(nxgep->mach, maddr->mma_addr,
		maddr->mma_addrlen)) {
		mutex_exit(nxgep->genlock);
		return (EINVAL);
	}
	/*
	 * 	Search for the first available slot. Because naddrfree
	 * is not zero, we are guaranteed to find one.
	 * 	Slot 0 is for unique (primary) MAC. The first alternate
	 * MAC slot is slot 1.
	 *	Each of the first two ports of Neptune has 16 alternate
	 * MAC slots but only the first 7 (or 15) slots have assigned factory
	 * MAC addresses. We first search among the slots without bundled
	 * factory MACs. If we fail to find one in that range, then we
	 * search the slots with bundled factory MACs.  A factory MAC
	 * will be wasted while the slot is used with a user MAC address.
	 * But the slot could be used by factory MAC again after calling
	 * nxge_m_mmac_remove and nxge_m_mmac_reserve.
	 */
	if (mmac_info->num_factory_mmac < mmac_info->num_mmac) {
		for (slot = mmac_info->num_factory_mmac + 1;
			slot <= mmac_info->num_mmac; slot++) {
			if (!(mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED))
				break;
		}
		if (slot > mmac_info->num_mmac) {
			for (slot = 1; slot <= mmac_info->num_factory_mmac;
				slot++) {
				if (!(mmac_info->mac_pool[slot].flags
					& MMAC_SLOT_USED))
					break;
			}
		}
	} else {
		for (slot = 1; slot <= mmac_info->num_mmac; slot++) {
			if (!(mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED))
				break;
		}
	}
	ASSERT(slot <= mmac_info->num_mmac);
	if ((err = nxge_altmac_set(nxgep, maddr->mma_addr, slot)) != 0) {
		mutex_exit(nxgep->genlock);
		return (err);
	}
	bcopy(maddr->mma_addr, mmac_info->mac_pool[slot].addr, ETHERADDRL);
	mmac_info->mac_pool[slot].flags |= MMAC_SLOT_USED;
	mmac_info->mac_pool[slot].flags &= ~MMAC_VENDOR_ADDR;
	mmac_info->naddrfree--;
	nxge_mmac_kstat_update(nxgep, slot, B_FALSE);

	maddr->mma_slot = slot;

	mutex_exit(nxgep->genlock);
	return (0);
}

/*
 * This function reserves an unused slot and programs the slot and the HW
 * with a factory mac address.
 */
static int
nxge_m_mmac_reserve(void *arg, mac_multi_addr_t *maddr)
{
	p_nxge_t nxgep = arg;
	mac_addr_slot_t slot;
	nxge_mmac_t *mmac_info;
	int err;
	nxge_status_t status;

	mutex_enter(nxgep->genlock);

	/*
	 * Make sure that nxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = nxge_init(nxgep);
		if (status != NXGE_OK) {
			mutex_exit(nxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &nxgep->nxge_mmac_info;
	if (mmac_info->naddrfree == 0) {
		mutex_exit(nxgep->genlock);
		return (ENOSPC);
	}

	slot = maddr->mma_slot;
	if (slot == -1) {  /* -1: Take the first available slot */
		for (slot = 1; slot <= mmac_info->num_factory_mmac; slot++) {
			if (!(mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED))
				break;
		}
		if (slot > mmac_info->num_factory_mmac) {
			mutex_exit(nxgep->genlock);
			return (ENOSPC);
		}
	}
	if (slot < 1 || slot > mmac_info->num_factory_mmac) {
		/*
		 * Do not support factory MAC at a slot greater than
		 * num_factory_mmac even when there are available factory
		 * MAC addresses because the alternate MACs are bundled with
		 * slot[1] through slot[num_factory_mmac]
		 */
		mutex_exit(nxgep->genlock);
		return (EINVAL);
	}
	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED) {
		mutex_exit(nxgep->genlock);
		return (EBUSY);
	}
	/* Verify the address to be reserved */
	if (!mac_unicst_verify(nxgep->mach,
		mmac_info->factory_mac_pool[slot], ETHERADDRL)) {
		mutex_exit(nxgep->genlock);
		return (EINVAL);
	}
	if (err = nxge_altmac_set(nxgep,
		mmac_info->factory_mac_pool[slot], slot)) {
		mutex_exit(nxgep->genlock);
		return (err);
	}
	bcopy(mmac_info->factory_mac_pool[slot], maddr->mma_addr, ETHERADDRL);
	mmac_info->mac_pool[slot].flags |= MMAC_SLOT_USED | MMAC_VENDOR_ADDR;
	mmac_info->naddrfree--;

	nxge_mmac_kstat_update(nxgep, slot, B_TRUE);
	mutex_exit(nxgep->genlock);

	/* Pass info back to the caller */
	maddr->mma_slot = slot;
	maddr->mma_addrlen = ETHERADDRL;
	maddr->mma_flags = MMAC_SLOT_USED | MMAC_VENDOR_ADDR;

	return (0);
}

/*
 * Remove the specified mac address and update the HW not to filter
 * the mac address anymore.
 */
static int
nxge_m_mmac_remove(void *arg, mac_addr_slot_t slot)
{
	p_nxge_t nxgep = arg;
	nxge_mmac_t *mmac_info;
	uint8_t addrn;
	uint8_t portn;
	int err = 0;
	nxge_status_t status;

	mutex_enter(nxgep->genlock);

	/*
	 * Make sure that nxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = nxge_init(nxgep);
		if (status != NXGE_OK) {
			mutex_exit(nxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &nxgep->nxge_mmac_info;
	if (slot < 1 || slot > mmac_info->num_mmac) {
		mutex_exit(nxgep->genlock);
		return (EINVAL);
	}

	portn = nxgep->mac.portnum;
	if (portn == XMAC_PORT_0 || portn == XMAC_PORT_1)
		addrn = (uint8_t)slot - 1;
	else
		addrn = (uint8_t)slot;

	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED) {
		if (npi_mac_altaddr_disable(nxgep->npi_handle, portn, addrn)
				== NPI_SUCCESS) {
			mmac_info->naddrfree++;
			mmac_info->mac_pool[slot].flags &= ~MMAC_SLOT_USED;
			/*
			 * Regardless if the MAC we just stopped filtering
			 * is a user addr or a facory addr, we must set
			 * the MMAC_VENDOR_ADDR flag if this slot has an
			 * associated factory MAC to indicate that a factory
			 * MAC is available.
			 */
			if (slot <= mmac_info->num_factory_mmac) {
				mmac_info->mac_pool[slot].flags
					|= MMAC_VENDOR_ADDR;
			}
			/*
			 * Clear mac_pool[slot].addr so that kstat shows 0
			 * alternate MAC address if the slot is not used.
			 * (But nxge_m_mmac_get returns the factory MAC even
			 * when the slot is not used!)
			 */
			bzero(mmac_info->mac_pool[slot].addr, ETHERADDRL);
			nxge_mmac_kstat_update(nxgep, slot, B_FALSE);
		} else {
			err = EIO;
		}
	} else {
		err = EINVAL;
	}

	mutex_exit(nxgep->genlock);
	return (err);
}


/*
 * Modify a mac address added by nxge_m_mmac_add or nxge_m_mmac_reserve().
 */
static int
nxge_m_mmac_modify(void *arg, mac_multi_addr_t *maddr)
{
	p_nxge_t nxgep = arg;
	mac_addr_slot_t slot;
	nxge_mmac_t *mmac_info;
	int err = 0;
	nxge_status_t status;

	if (!mac_unicst_verify(nxgep->mach, maddr->mma_addr,
			maddr->mma_addrlen))
		return (EINVAL);

	slot = maddr->mma_slot;

	mutex_enter(nxgep->genlock);

	/*
	 * Make sure that nxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = nxge_init(nxgep);
		if (status != NXGE_OK) {
			mutex_exit(nxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &nxgep->nxge_mmac_info;
	if (slot < 1 || slot > mmac_info->num_mmac) {
		mutex_exit(nxgep->genlock);
		return (EINVAL);
	}
	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED) {
		if ((err = nxge_altmac_set(nxgep, maddr->mma_addr, slot))
			!= 0) {
			bcopy(maddr->mma_addr, mmac_info->mac_pool[slot].addr,
				ETHERADDRL);
			/*
			 * Assume that the MAC passed down from the caller
			 * is not a factory MAC address (The user should
			 * call mmac_remove followed by mmac_reserve if
			 * he wants to use the factory MAC for this slot).
			 */
			mmac_info->mac_pool[slot].flags &= ~MMAC_VENDOR_ADDR;
			nxge_mmac_kstat_update(nxgep, slot, B_FALSE);
		}
	} else {
		err = EINVAL;
	}
	mutex_exit(nxgep->genlock);
	return (err);
}

/*
 * nxge_m_mmac_get() - Get the MAC address and other information
 * related to the slot.  mma_flags should be set to 0 in the call.
 * Note: although kstat shows MAC address as zero when a slot is
 * not used, Crossbow expects nxge_m_mmac_get to copy factory MAC
 * to the caller as long as the slot is not using a user MAC address.
 * The following table shows the rules,
 *
 *				   USED    VENDOR    mma_addr
 * ------------------------------------------------------------
 * (1) Slot uses a user MAC:        yes      no     user MAC
 * (2) Slot uses a factory MAC:     yes      yes    factory MAC
 * (3) Slot is not used but is
 *     factory MAC capable:         no       yes    factory MAC
 * (4) Slot is not used and is
 *     not factory MAC capable:     no       no        0
 * ------------------------------------------------------------
 */
static int
nxge_m_mmac_get(void *arg, mac_multi_addr_t *maddr)
{
	nxge_t *nxgep = arg;
	mac_addr_slot_t slot;
	nxge_mmac_t *mmac_info;
	nxge_status_t status;

	slot = maddr->mma_slot;

	mutex_enter(nxgep->genlock);

	/*
	 * Make sure that nxge is initialized, if _start() has
	 * not been called.
	 */
	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		status = nxge_init(nxgep);
		if (status != NXGE_OK) {
			mutex_exit(nxgep->genlock);
			return (ENXIO);
		}
	}

	mmac_info = &nxgep->nxge_mmac_info;

	if (slot < 1 || slot > mmac_info->num_mmac) {
		mutex_exit(nxgep->genlock);
		return (EINVAL);
	}
	maddr->mma_flags = 0;
	if (mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED)
		maddr->mma_flags |= MMAC_SLOT_USED;

	if (mmac_info->mac_pool[slot].flags & MMAC_VENDOR_ADDR) {
		maddr->mma_flags |= MMAC_VENDOR_ADDR;
		bcopy(mmac_info->factory_mac_pool[slot],
			maddr->mma_addr, ETHERADDRL);
		maddr->mma_addrlen = ETHERADDRL;
	} else {
		if (maddr->mma_flags & MMAC_SLOT_USED) {
			bcopy(mmac_info->mac_pool[slot].addr,
				maddr->mma_addr, ETHERADDRL);
			maddr->mma_addrlen = ETHERADDRL;
		} else {
			bzero(maddr->mma_addr, ETHERADDRL);
			maddr->mma_addrlen = 0;
		}
	}
	mutex_exit(nxgep->genlock);
	return (0);
}


static boolean_t
nxge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	nxge_t *nxgep = arg;
	uint32_t *txflags = cap_data;
	multiaddress_capab_t *mmacp = cap_data;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		*txflags = HCKSUM_INET_PARTIAL;
		break;
	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, simply returning
		 * B_TRUE stating that we support polling is sufficient.
		 */
		break;

	case MAC_CAPAB_MULTIADDRESS:
		mutex_enter(nxgep->genlock);

		mmacp->maddr_naddr = nxgep->nxge_mmac_info.num_mmac;
		mmacp->maddr_naddrfree = nxgep->nxge_mmac_info.naddrfree;
		mmacp->maddr_flag = 0; /* 0 is requried by PSARC2006/265 */
		/*
		 * maddr_handle is driver's private data, passed back to
		 * entry point functions as arg.
		 */
		mmacp->maddr_handle	= nxgep;
		mmacp->maddr_add	= nxge_m_mmac_add;
		mmacp->maddr_remove	= nxge_m_mmac_remove;
		mmacp->maddr_modify	= nxge_m_mmac_modify;
		mmacp->maddr_get	= nxge_m_mmac_get;
		mmacp->maddr_reserve	= nxge_m_mmac_reserve;

		mutex_exit(nxgep->genlock);
		break;
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (nxge_lso_enable) {
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			if (nxge_lso_max > NXGE_LSO_MAXLEN) {
				nxge_lso_max = NXGE_LSO_MAXLEN;
			}
			cap_lso->lso_basic_tcp_ipv4.lso_max = nxge_lso_max;
			break;
		} else {
			return (B_FALSE);
		}
	}

	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Module loading and removing entry points.
 */

static	struct cb_ops 	nxge_cb_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,
	D_MP, 			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

static struct dev_ops nxge_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	nulldev,
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	nxge_attach,		/* devo_attach */
	nxge_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&nxge_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL, /* devo_bus_ops	*/
	ddi_power		/* devo_power */
};

extern	struct	mod_ops	mod_driverops;

#define	NXGE_DESC_VER		"Sun NIU 10Gb Ethernet"

/*
 * Module linkage information for the kernel.
 */
static struct modldrv 	nxge_modldrv = {
	&mod_driverops,
	NXGE_DESC_VER,
	&nxge_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &nxge_modldrv, NULL
};

int
_init(void)
{
	int		status;

	NXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _init"));
	mac_init_ops(&nxge_dev_ops, "nxge");
	status = ddi_soft_state_init(&nxge_list, sizeof (nxge_t), 0);
	if (status != 0) {
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL,
			"failed to init device soft state"));
		goto _init_exit;
	}
	status = mod_install(&modlinkage);
	if (status != 0) {
		ddi_soft_state_fini(&nxge_list);
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL, "Mod install failed"));
		goto _init_exit;
	}

	MUTEX_INIT(&nxge_common_lock, NULL, MUTEX_DRIVER, NULL);

_init_exit:
	NXGE_DEBUG_MSG((NULL, MOD_CTL, "_init status = 0x%X", status));

	return (status);
}

int
_fini(void)
{
	int		status;

	NXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _fini"));

	NXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _fini: mod_remove"));

	if (nxge_mblks_pending)
		return (EBUSY);

	status = mod_remove(&modlinkage);
	if (status != DDI_SUCCESS) {
		NXGE_DEBUG_MSG((NULL, MOD_CTL,
			    "Module removal failed 0x%08x",
			    status));
		goto _fini_exit;
	}

	mac_fini_ops(&nxge_dev_ops);

	ddi_soft_state_fini(&nxge_list);

	MUTEX_DESTROY(&nxge_common_lock);
_fini_exit:
	NXGE_DEBUG_MSG((NULL, MOD_CTL, "_fini status = 0x%08x", status));

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	int		status;

	NXGE_DEBUG_MSG((NULL, MOD_CTL, "==> _info"));
	status = mod_info(&modlinkage, modinfop);
	NXGE_DEBUG_MSG((NULL, MOD_CTL, " _info status = 0x%X", status));

	return (status);
}

/*ARGSUSED*/
static nxge_status_t
nxge_add_intrs(p_nxge_t nxgep)
{

	int		intr_types;
	int		type = 0;
	int		ddi_status = DDI_SUCCESS;
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs"));

	nxgep->nxge_intr_type.intr_registered = B_FALSE;
	nxgep->nxge_intr_type.intr_enabled = B_FALSE;
	nxgep->nxge_intr_type.msi_intx_cnt = 0;
	nxgep->nxge_intr_type.intr_added = 0;
	nxgep->nxge_intr_type.niu_msi_enable = B_FALSE;
	nxgep->nxge_intr_type.intr_type = 0;

	if (nxgep->niu_type == N2_NIU) {
		nxgep->nxge_intr_type.niu_msi_enable = B_TRUE;
	} else if (nxge_msi_enable) {
		nxgep->nxge_intr_type.niu_msi_enable = B_TRUE;
	}

	/* Get the supported interrupt types */
	if ((ddi_status = ddi_intr_get_supported_types(nxgep->dip, &intr_types))
			!= DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "<== nxge_add_intrs: "
			"ddi_intr_get_supported_types failed: status 0x%08x",
			ddi_status));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}
	nxgep->nxge_intr_type.intr_types = intr_types;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs: "
		"ddi_intr_get_supported_types: 0x%08x", intr_types));

	/*
	 * Solaris MSIX is not supported yet. use MSI for now.
	 * nxge_msi_enable (1):
	 *	1 - MSI		2 - MSI-X	others - FIXED
	 */
	switch (nxge_msi_enable) {
	default:
		type = DDI_INTR_TYPE_FIXED;
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_add_intrs: "
			"use fixed (intx emulation) type %08x",
			type));
		break;

	case 2:
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_add_intrs: "
			"ddi_intr_get_supported_types: 0x%08x", intr_types));
		if (intr_types & DDI_INTR_TYPE_MSIX) {
			type = DDI_INTR_TYPE_MSIX;
			NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs: "
				"ddi_intr_get_supported_types: MSIX 0x%08x",
				type));
		} else if (intr_types & DDI_INTR_TYPE_MSI) {
			type = DDI_INTR_TYPE_MSI;
			NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs: "
				"ddi_intr_get_supported_types: MSI 0x%08x",
				type));
		} else if (intr_types & DDI_INTR_TYPE_FIXED) {
			type = DDI_INTR_TYPE_FIXED;
			NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_add_intrs: "
				"ddi_intr_get_supported_types: MSXED0x%08x",
				type));
		}
		break;

	case 1:
		if (intr_types & DDI_INTR_TYPE_MSI) {
			type = DDI_INTR_TYPE_MSI;
			NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_add_intrs: "
				"ddi_intr_get_supported_types: MSI 0x%08x",
				type));
		} else if (intr_types & DDI_INTR_TYPE_MSIX) {
			type = DDI_INTR_TYPE_MSIX;
			NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs: "
				"ddi_intr_get_supported_types: MSIX 0x%08x",
				type));
		} else if (intr_types & DDI_INTR_TYPE_FIXED) {
			type = DDI_INTR_TYPE_FIXED;
			NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs: "
				"ddi_intr_get_supported_types: MSXED0x%08x",
				type));
		}
	}

	nxgep->nxge_intr_type.intr_type = type;
	if ((type == DDI_INTR_TYPE_MSIX || type == DDI_INTR_TYPE_MSI ||
		type == DDI_INTR_TYPE_FIXED) &&
			nxgep->nxge_intr_type.niu_msi_enable) {
		if ((status = nxge_add_intrs_adv(nxgep)) != DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    " nxge_add_intrs: "
				    " nxge_add_intrs_adv failed: status 0x%08x",
				    status));
			return (status);
		} else {
			NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs: "
			"interrupts registered : type %d", type));
			nxgep->nxge_intr_type.intr_registered = B_TRUE;

			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"\nAdded advanced nxge add_intr_adv "
					"intr type 0x%x\n", type));

			return (status);
		}
	}

	if (!nxgep->nxge_intr_type.intr_registered) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "==> nxge_add_intrs: "
			"failed to register interrupts"));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_add_intrs"));
	return (status);
}

/*ARGSUSED*/
static nxge_status_t
nxge_add_soft_intrs(p_nxge_t nxgep)
{

	int		ddi_status = DDI_SUCCESS;
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_soft_intrs"));

	nxgep->resched_id = NULL;
	nxgep->resched_running = B_FALSE;
	ddi_status = ddi_add_softintr(nxgep->dip, DDI_SOFTINT_LOW,
			&nxgep->resched_id,
		NULL, NULL, nxge_reschedule, (caddr_t)nxgep);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "<== nxge_add_soft_intrs: "
			"ddi_add_softintrs failed: status 0x%08x",
			ddi_status));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_ddi_add_soft_intrs"));

	return (status);
}

static nxge_status_t
nxge_add_intrs_adv(p_nxge_t nxgep)
{
	int		intr_type;
	p_nxge_intr_t	intrp;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs_adv"));

	intrp = (p_nxge_intr_t)&nxgep->nxge_intr_type;
	intr_type = intrp->intr_type;
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_add_intrs_adv: type 0x%x",
		intr_type));

	switch (intr_type) {
	case DDI_INTR_TYPE_MSI: /* 0x2 */
	case DDI_INTR_TYPE_MSIX: /* 0x4 */
		return (nxge_add_intrs_adv_type(nxgep, intr_type));

	case DDI_INTR_TYPE_FIXED: /* 0x1 */
		return (nxge_add_intrs_adv_type_fix(nxgep, intr_type));

	default:
		return (NXGE_ERROR);
	}
}


/*ARGSUSED*/
static nxge_status_t
nxge_add_intrs_adv_type(p_nxge_t nxgep, uint32_t int_type)
{
	dev_info_t		*dip = nxgep->dip;
	p_nxge_ldg_t		ldgp;
	p_nxge_intr_t		intrp;
	uint_t			*inthandler;
	void			*arg1, *arg2;
	int			behavior;
	int			nintrs, navail, nrequest;
	int			nactual, nrequired;
	int			inum = 0;
	int			x, y;
	int			ddi_status = DDI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_add_intrs_adv_type"));
	intrp = (p_nxge_intr_t)&nxgep->nxge_intr_type;
	intrp->start_inum = 0;

	ddi_status = ddi_intr_get_nintrs(dip, int_type, &nintrs);
	if ((ddi_status != DDI_SUCCESS) || (nintrs == 0)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"ddi_intr_get_nintrs() failed, status: 0x%x%, "
			    "nintrs: %d", ddi_status, nintrs));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	ddi_status = ddi_intr_get_navail(dip, int_type, &navail);
	if ((ddi_status != DDI_SUCCESS) || (navail == 0)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"ddi_intr_get_navail() failed, status: 0x%x%, "
			    "nintrs: %d", ddi_status, navail));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL,
		"ddi_intr_get_navail() returned: nintrs %d, navail %d",
		    nintrs, navail));

	/* PSARC/2007/453 MSI-X interrupt limit override */
	if (int_type == DDI_INTR_TYPE_MSIX) {
		nrequest = nxge_create_msi_property(nxgep);
		if (nrequest < navail) {
			navail = nrequest;
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
			    "nxge_add_intrs_adv_type: nintrs %d "
			    "navail %d (nrequest %d)",
			    nintrs, navail, nrequest));
		}
	}

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
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"ddi_intr_get_navail(): (msi power of 2) nintrs %d, "
			"navail %d", nintrs, navail));
	}

	behavior = ((int_type == DDI_INTR_TYPE_FIXED) ? DDI_INTR_ALLOC_STRICT :
			DDI_INTR_ALLOC_NORMAL);
	intrp->intr_size = navail * sizeof (ddi_intr_handle_t);
	intrp->htable = kmem_alloc(intrp->intr_size, KM_SLEEP);
	ddi_status = ddi_intr_alloc(dip, intrp->htable, int_type, inum,
		    navail, &nactual, behavior);
	if (ddi_status != DDI_SUCCESS || nactual == 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    " ddi_intr_alloc() failed: %d",
				    ddi_status));
		kmem_free(intrp->htable, intrp->intr_size);
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	if ((ddi_status = ddi_intr_get_pri(intrp->htable[0],
			(uint_t *)&intrp->pri)) != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    " ddi_intr_get_pri() failed: %d",
				    ddi_status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	nrequired = 0;
	switch (nxgep->niu_type) {
	default:
		status = nxge_ldgv_init(nxgep, &nactual, &nrequired);
		break;

	case N2_NIU:
		status = nxge_ldgv_init_n2(nxgep, &nactual, &nrequired);
		break;
	}

	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_add_intrs_adv_typ:nxge_ldgv_init "
			"failed: 0x%x", status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (status);
	}

	ldgp = nxgep->ldgvp->ldgp;
	for (x = 0; x < nrequired; x++, ldgp++) {
		ldgp->vector = (uint8_t)x;
		ldgp->intdata = SID_DATA(ldgp->func, x);
		arg1 = ldgp->ldvp;
		arg2 = nxgep;
		if (ldgp->nldvs == 1) {
			inthandler = (uint_t *)ldgp->ldvp->ldv_intr_handler;
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
				"nxge_add_intrs_adv_type: "
				"arg1 0x%x arg2 0x%x: "
				"1-1 int handler (entry %d intdata 0x%x)\n",
				arg1, arg2,
				x, ldgp->intdata));
		} else if (ldgp->nldvs > 1) {
			inthandler = (uint_t *)ldgp->sys_intr_handler;
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
				"nxge_add_intrs_adv_type: "
				"arg1 0x%x arg2 0x%x: "
				"nldevs %d int handler "
				"(entry %d intdata 0x%x)\n",
				arg1, arg2,
				ldgp->nldvs, x, ldgp->intdata));
		}

		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"==> nxge_add_intrs_adv_type: ddi_add_intr(inum) #%d "
			"htable 0x%llx", x, intrp->htable[x]));

		if ((ddi_status = ddi_intr_add_handler(intrp->htable[x],
			(ddi_intr_handler_t *)inthandler, arg1, arg2))
				!= DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_add_intrs_adv_type: failed #%d "
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

			(void) nxge_ldgv_uninit(nxgep);

			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}
		intrp->intr_added++;
	}

	intrp->msi_intx_cnt = nactual;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
		"Requested: %d, Allowed: %d msi_intx_cnt %d intr_added %d",
		navail, nactual,
		intrp->msi_intx_cnt,
		intrp->intr_added));

	(void) ddi_intr_get_cap(intrp->htable[0], &intrp->intr_cap);

	(void) nxge_intr_ldgv_init(nxgep);

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_add_intrs_adv_type"));

	return (status);
}

/*ARGSUSED*/
static nxge_status_t
nxge_add_intrs_adv_type_fix(p_nxge_t nxgep, uint32_t int_type)
{
	dev_info_t		*dip = nxgep->dip;
	p_nxge_ldg_t		ldgp;
	p_nxge_intr_t		intrp;
	uint_t			*inthandler;
	void			*arg1, *arg2;
	int			behavior;
	int			nintrs, navail;
	int			nactual, nrequired;
	int			inum = 0;
	int			x, y;
	int			ddi_status = DDI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_add_intrs_adv_type_fix"));
	intrp = (p_nxge_intr_t)&nxgep->nxge_intr_type;
	intrp->start_inum = 0;

	ddi_status = ddi_intr_get_nintrs(dip, int_type, &nintrs);
	if ((ddi_status != DDI_SUCCESS) || (nintrs == 0)) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"ddi_intr_get_nintrs() failed, status: 0x%x%, "
			    "nintrs: %d", status, nintrs));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	ddi_status = ddi_intr_get_navail(dip, int_type, &navail);
	if ((ddi_status != DDI_SUCCESS) || (navail == 0)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"ddi_intr_get_navail() failed, status: 0x%x%, "
			    "nintrs: %d", ddi_status, navail));
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL,
		"ddi_intr_get_navail() returned: nintrs %d, naavail %d",
		    nintrs, navail));

	behavior = ((int_type == DDI_INTR_TYPE_FIXED) ? DDI_INTR_ALLOC_STRICT :
			DDI_INTR_ALLOC_NORMAL);
	intrp->intr_size = navail * sizeof (ddi_intr_handle_t);
	intrp->htable = kmem_alloc(intrp->intr_size, KM_SLEEP);
	ddi_status = ddi_intr_alloc(dip, intrp->htable, int_type, inum,
		    navail, &nactual, behavior);
	if (ddi_status != DDI_SUCCESS || nactual == 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    " ddi_intr_alloc() failed: %d",
			    ddi_status));
		kmem_free(intrp->htable, intrp->intr_size);
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	if ((ddi_status = ddi_intr_get_pri(intrp->htable[0],
			(uint_t *)&intrp->pri)) != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    " ddi_intr_get_pri() failed: %d",
				    ddi_status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (NXGE_ERROR | NXGE_DDI_FAILED);
	}

	nrequired = 0;
	switch (nxgep->niu_type) {
	default:
		status = nxge_ldgv_init(nxgep, &nactual, &nrequired);
		break;

	case N2_NIU:
		status = nxge_ldgv_init_n2(nxgep, &nactual, &nrequired);
		break;
	}

	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_add_intrs_adv_type_fix:nxge_ldgv_init "
			"failed: 0x%x", status));
		/* Free already allocated interrupts */
		for (y = 0; y < nactual; y++) {
			(void) ddi_intr_free(intrp->htable[y]);
		}

		kmem_free(intrp->htable, intrp->intr_size);
		return (status);
	}

	ldgp = nxgep->ldgvp->ldgp;
	for (x = 0; x < nrequired; x++, ldgp++) {
		ldgp->vector = (uint8_t)x;
		if (nxgep->niu_type != N2_NIU) {
			ldgp->intdata = SID_DATA(ldgp->func, x);
		}

		arg1 = ldgp->ldvp;
		arg2 = nxgep;
		if (ldgp->nldvs == 1) {
			inthandler = (uint_t *)ldgp->ldvp->ldv_intr_handler;
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
				"nxge_add_intrs_adv_type_fix: "
				"1-1 int handler(%d) ldg %d ldv %d "
				"arg1 $%p arg2 $%p\n",
				x, ldgp->ldg, ldgp->ldvp->ldv,
				arg1, arg2));
		} else if (ldgp->nldvs > 1) {
			inthandler = (uint_t *)ldgp->sys_intr_handler;
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
				"nxge_add_intrs_adv_type_fix: "
				"shared ldv %d int handler(%d) ldv %d ldg %d"
				"arg1 0x%016llx arg2 0x%016llx\n",
				x, ldgp->nldvs, ldgp->ldg, ldgp->ldvp->ldv,
				arg1, arg2));
		}

		if ((ddi_status = ddi_intr_add_handler(intrp->htable[x],
			(ddi_intr_handler_t *)inthandler, arg1, arg2))
				!= DDI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_add_intrs_adv_type_fix: failed #%d "
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

			(void) nxge_ldgv_uninit(nxgep);

			return (NXGE_ERROR | NXGE_DDI_FAILED);
		}
		intrp->intr_added++;
	}

	intrp->msi_intx_cnt = nactual;

	(void) ddi_intr_get_cap(intrp->htable[0], &intrp->intr_cap);

	status = nxge_intr_ldgv_init(nxgep);
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_add_intrs_adv_type_fix"));

	return (status);
}

static void
nxge_remove_intrs(p_nxge_t nxgep)
{
	int		i, inum;
	p_nxge_intr_t	intrp;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_remove_intrs"));
	intrp = (p_nxge_intr_t)&nxgep->nxge_intr_type;
	if (!intrp->intr_registered) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"<== nxge_remove_intrs: interrupts not registered"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_remove_intrs:advanced"));

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
			NXGE_DEBUG_MSG((nxgep, DDI_CTL,
				"nxge_remove_intrs: ddi_intr_free inum %d "
				"msi_intx_cnt %d intr_added %d",
				inum,
				intrp->msi_intx_cnt,
				intrp->intr_added));

			(void) ddi_intr_free(intrp->htable[inum]);
		}
	}

	kmem_free(intrp->htable, intrp->intr_size);
	intrp->intr_registered = B_FALSE;
	intrp->intr_enabled = B_FALSE;
	intrp->msi_intx_cnt = 0;
	intrp->intr_added = 0;

	(void) nxge_ldgv_uninit(nxgep);

	(void) ddi_prop_remove(DDI_DEV_T_NONE, nxgep->dip,
	    "#msix-request");

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_remove_intrs"));
}

/*ARGSUSED*/
static void
nxge_remove_soft_intrs(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_remove_soft_intrs"));
	if (nxgep->resched_id) {
		ddi_remove_softintr(nxgep->resched_id);
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"==> nxge_remove_soft_intrs: removed"));
		nxgep->resched_id = NULL;
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_remove_soft_intrs"));
}

/*ARGSUSED*/
static void
nxge_intrs_enable(p_nxge_t nxgep)
{
	p_nxge_intr_t	intrp;
	int		i;
	int		status;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intrs_enable"));

	intrp = (p_nxge_intr_t)&nxgep->nxge_intr_type;

	if (!intrp->intr_registered) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "<== nxge_intrs_enable: "
			"interrupts are not registered"));
		return;
	}

	if (intrp->intr_enabled) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"<== nxge_intrs_enable: already enabled"));
		return;
	}

	if (intrp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		status = ddi_intr_block_enable(intrp->htable,
			intrp->intr_added);
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intrs_enable "
			"block enable - status 0x%x total inums #%d\n",
			status, intrp->intr_added));
	} else {
		for (i = 0; i < intrp->intr_added; i++) {
			status = ddi_intr_enable(intrp->htable[i]);
			NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intrs_enable "
				"ddi_intr_enable:enable - status 0x%x "
				"total inums %d enable inum #%d\n",
				status, intrp->intr_added, i));
			if (status == DDI_SUCCESS) {
				intrp->intr_enabled = B_TRUE;
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_intrs_enable"));
}

/*ARGSUSED*/
static void
nxge_intrs_disable(p_nxge_t nxgep)
{
	p_nxge_intr_t	intrp;
	int		i;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_intrs_disable"));

	intrp = (p_nxge_intr_t)&nxgep->nxge_intr_type;

	if (!intrp->intr_registered) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_intrs_disable: "
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
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_intrs_disable"));
}

static nxge_status_t
nxge_mac_register(p_nxge_t nxgep)
{
	mac_register_t *macp;
	int		status;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_mac_register"));

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		return (NXGE_ERROR);

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = nxgep;
	macp->m_dip = nxgep->dip;
	macp->m_src_addr = nxgep->ouraddr.ether_addr_octet;
	macp->m_callbacks = &nxge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = nxgep->mac.maxframesize -
		sizeof (struct ether_header) - ETHERFCSL - 4;
	macp->m_margin = VLAN_TAGSZ;

	status = mac_register(macp, &nxgep->mach);
	mac_free(macp);

	if (status != 0) {
		cmn_err(CE_WARN,
			"!nxge_mac_register failed (status %d instance %d)",
			status, nxgep->instance);
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_mac_register success "
		"(instance %d)", nxgep->instance));

	return (NXGE_OK);
}

void
nxge_err_inject(p_nxge_t nxgep, queue_t *wq, mblk_t *mp)
{
	ssize_t		size;
	mblk_t		*nmp;
	uint8_t		blk_id;
	uint8_t		chan;
	uint32_t	err_id;
	err_inject_t	*eip;

	NXGE_DEBUG_MSG((nxgep, STR_CTL, "==> nxge_err_inject"));

	size = 1024;
	nmp = mp->b_cont;
	eip = (err_inject_t *)nmp->b_rptr;
	blk_id = eip->blk_id;
	err_id = eip->err_id;
	chan = eip->chan;
	cmn_err(CE_NOTE, "!blk_id = 0x%x\n", blk_id);
	cmn_err(CE_NOTE, "!err_id = 0x%x\n", err_id);
	cmn_err(CE_NOTE, "!chan = 0x%x\n", chan);
	switch (blk_id) {
	case MAC_BLK_ID:
		break;
	case TXMAC_BLK_ID:
		break;
	case RXMAC_BLK_ID:
		break;
	case MIF_BLK_ID:
		break;
	case IPP_BLK_ID:
		nxge_ipp_inject_err(nxgep, err_id);
		break;
	case TXC_BLK_ID:
		nxge_txc_inject_err(nxgep, err_id);
		break;
	case TXDMA_BLK_ID:
		nxge_txdma_inject_err(nxgep, err_id, chan);
		break;
	case RXDMA_BLK_ID:
		nxge_rxdma_inject_err(nxgep, err_id, chan);
		break;
	case ZCP_BLK_ID:
		nxge_zcp_inject_err(nxgep, err_id);
		break;
	case ESPC_BLK_ID:
		break;
	case FFLP_BLK_ID:
		break;
	case PHY_BLK_ID:
		break;
	case ETHER_SERDES_BLK_ID:
		break;
	case PCIE_SERDES_BLK_ID:
		break;
	case VIR_BLK_ID:
		break;
	}

	nmp->b_wptr = nmp->b_rptr + size;
	NXGE_DEBUG_MSG((nxgep, STR_CTL, "<== nxge_err_inject"));

	miocack(wq, mp, (int)size, 0);
}

static int
nxge_init_common_dev(p_nxge_t nxgep)
{
	p_nxge_hw_list_t	hw_p;
	dev_info_t 		*p_dip;

	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "==> nxge_init_common_device"));

	p_dip = nxgep->p_dip;
	MUTEX_ENTER(&nxge_common_lock);
	NXGE_DEBUG_MSG((nxgep, MOD_CTL,
		"==> nxge_init_common_dev:func # %d",
			nxgep->function_num));
	/*
	 * Loop through existing per neptune hardware list.
	 */
	for (hw_p = nxge_hw_list; hw_p; hw_p = hw_p->next) {
		NXGE_DEBUG_MSG((nxgep, MOD_CTL,
			"==> nxge_init_common_device:func # %d "
			"hw_p $%p parent dip $%p",
			nxgep->function_num,
			hw_p,
			p_dip));
		if (hw_p->parent_devp == p_dip) {
			nxgep->nxge_hw_p = hw_p;
			hw_p->ndevs++;
			hw_p->nxge_p[nxgep->function_num] = nxgep;
			NXGE_DEBUG_MSG((nxgep, MOD_CTL,
				"==> nxge_init_common_device:func # %d "
				"hw_p $%p parent dip $%p "
				"ndevs %d (found)",
				nxgep->function_num,
				hw_p,
				p_dip,
				hw_p->ndevs));
			break;
		}
	}

	if (hw_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, MOD_CTL,
			"==> nxge_init_common_device:func # %d "
			"parent dip $%p (new)",
			nxgep->function_num,
			p_dip));
		hw_p = kmem_zalloc(sizeof (nxge_hw_list_t), KM_SLEEP);
		hw_p->parent_devp = p_dip;
		hw_p->magic = NXGE_NEPTUNE_MAGIC;
		nxgep->nxge_hw_p = hw_p;
		hw_p->ndevs++;
		hw_p->nxge_p[nxgep->function_num] = nxgep;
		hw_p->next = nxge_hw_list;
		if (nxgep->niu_type == N2_NIU) {
			hw_p->niu_type = N2_NIU;
			hw_p->platform_type = P_NEPTUNE_NIU;
		} else {
			hw_p->niu_type = NIU_TYPE_NONE;
			hw_p->platform_type = P_NEPTUNE_NONE;
		}

		MUTEX_INIT(&hw_p->nxge_cfg_lock, NULL, MUTEX_DRIVER, NULL);
		MUTEX_INIT(&hw_p->nxge_tcam_lock, NULL, MUTEX_DRIVER, NULL);
		MUTEX_INIT(&hw_p->nxge_vlan_lock, NULL, MUTEX_DRIVER, NULL);
		MUTEX_INIT(&hw_p->nxge_mdio_lock, NULL, MUTEX_DRIVER, NULL);
		MUTEX_INIT(&hw_p->nxge_mii_lock, NULL, MUTEX_DRIVER, NULL);

		nxge_hw_list = hw_p;

		(void) nxge_scan_ports_phy(nxgep, nxge_hw_list);
	}

	MUTEX_EXIT(&nxge_common_lock);

	nxgep->platform_type = hw_p->platform_type;
	if (nxgep->niu_type != N2_NIU) {
		nxgep->niu_type = hw_p->niu_type;
	}

	NXGE_DEBUG_MSG((nxgep, MOD_CTL,
		"==> nxge_init_common_device (nxge_hw_list) $%p",
		nxge_hw_list));
	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "<== nxge_init_common_device"));

	return (NXGE_OK);
}

static void
nxge_uninit_common_dev(p_nxge_t nxgep)
{
	p_nxge_hw_list_t	hw_p, h_hw_p;
	dev_info_t 		*p_dip;

	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "==> nxge_uninit_common_device"));
	if (nxgep->nxge_hw_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, MOD_CTL,
			"<== nxge_uninit_common_device (no common)"));
		return;
	}

	MUTEX_ENTER(&nxge_common_lock);
	h_hw_p = nxge_hw_list;
	for (hw_p = nxge_hw_list; hw_p; hw_p = hw_p->next) {
		p_dip = hw_p->parent_devp;
		if (nxgep->nxge_hw_p == hw_p &&
			p_dip == nxgep->p_dip &&
			nxgep->nxge_hw_p->magic == NXGE_NEPTUNE_MAGIC &&
			hw_p->magic == NXGE_NEPTUNE_MAGIC) {

			NXGE_DEBUG_MSG((nxgep, MOD_CTL,
				"==> nxge_uninit_common_device:func # %d "
				"hw_p $%p parent dip $%p "
				"ndevs %d (found)",
				nxgep->function_num,
				hw_p,
				p_dip,
				hw_p->ndevs));

			nxgep->nxge_hw_p = NULL;
			if (hw_p->ndevs) {
				hw_p->ndevs--;
			}
			hw_p->nxge_p[nxgep->function_num] = NULL;
			if (!hw_p->ndevs) {
				MUTEX_DESTROY(&hw_p->nxge_vlan_lock);
				MUTEX_DESTROY(&hw_p->nxge_tcam_lock);
				MUTEX_DESTROY(&hw_p->nxge_cfg_lock);
				MUTEX_DESTROY(&hw_p->nxge_mdio_lock);
				MUTEX_DESTROY(&hw_p->nxge_mii_lock);
				NXGE_DEBUG_MSG((nxgep, MOD_CTL,
					"==> nxge_uninit_common_device: "
					"func # %d "
					"hw_p $%p parent dip $%p "
					"ndevs %d (last)",
					nxgep->function_num,
					hw_p,
					p_dip,
					hw_p->ndevs));

				if (hw_p == nxge_hw_list) {
					NXGE_DEBUG_MSG((nxgep, MOD_CTL,
						"==> nxge_uninit_common_device:"
						"remove head func # %d "
						"hw_p $%p parent dip $%p "
						"ndevs %d (head)",
						nxgep->function_num,
						hw_p,
						p_dip,
						hw_p->ndevs));
					nxge_hw_list = hw_p->next;
				} else {
					NXGE_DEBUG_MSG((nxgep, MOD_CTL,
						"==> nxge_uninit_common_device:"
						"remove middle func # %d "
						"hw_p $%p parent dip $%p "
						"ndevs %d (middle)",
						nxgep->function_num,
						hw_p,
						p_dip,
						hw_p->ndevs));
					h_hw_p->next = hw_p->next;
				}

				KMEM_FREE(hw_p, sizeof (nxge_hw_list_t));
			}
			break;
		} else {
			h_hw_p = hw_p;
		}
	}

	MUTEX_EXIT(&nxge_common_lock);
	NXGE_DEBUG_MSG((nxgep, MOD_CTL,
		"==> nxge_uninit_common_device (nxge_hw_list) $%p",
		nxge_hw_list));

	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "<= nxge_uninit_common_device"));
}

/*
 * Determines the number of ports from the niu_type or the platform type.
 * Returns the number of ports, or returns zero on failure.
 */

int
nxge_get_nports(p_nxge_t nxgep)
{
	int	nports = 0;

	switch (nxgep->niu_type) {
	case N2_NIU:
	case NEPTUNE_2_10GF:
		nports = 2;
		break;
	case NEPTUNE_4_1GC:
	case NEPTUNE_2_10GF_2_1GC:
	case NEPTUNE_1_10GF_3_1GC:
	case NEPTUNE_1_1GC_1_10GF_2_1GC:
		nports = 4;
		break;
	default:
		switch (nxgep->platform_type) {
		case P_NEPTUNE_NIU:
		case P_NEPTUNE_ATLAS_2PORT:
			nports = 2;
			break;
		case P_NEPTUNE_ATLAS_4PORT:
		case P_NEPTUNE_MARAMBA_P0:
		case P_NEPTUNE_MARAMBA_P1:
		case P_NEPTUNE_ALONSO:
			nports = 4;
			break;
		default:
			break;
		}
		break;
	}

	return (nports);
}

/*
 * The following two functions are to support
 * PSARC/2007/453 MSI-X interrupt limit override.
 */
static int
nxge_create_msi_property(p_nxge_t nxgep)
{
	int	nmsi;
	extern	int ncpus;

	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "==>nxge_create_msi_property"));

	switch (nxgep->mac.portmode) {
	case PORT_10G_COPPER:
	case PORT_10G_FIBER:
		(void) ddi_prop_create(DDI_DEV_T_NONE, nxgep->dip,
		    DDI_PROP_CANSLEEP, "#msix-request", NULL, 0);
		/*
		 * The maximum MSI-X requested will be 8.
		 * If the # of CPUs is less than 8, we will reqeust
		 * # MSI-X based on the # of CPUs.
		 */
		if (ncpus >= NXGE_MSIX_REQUEST_10G) {
			nmsi = NXGE_MSIX_REQUEST_10G;
		} else {
			nmsi = ncpus;
		}
		NXGE_DEBUG_MSG((nxgep, MOD_CTL,
		    "==>nxge_create_msi_property(10G): exists 0x%x (nmsi %d)",
		    ddi_prop_exists(DDI_DEV_T_NONE, nxgep->dip,
		    DDI_PROP_CANSLEEP, "#msix-request"), nmsi));
		break;

	default:
		nmsi = NXGE_MSIX_REQUEST_1G;
		NXGE_DEBUG_MSG((nxgep, MOD_CTL,
		    "==>nxge_create_msi_property(1G): exists 0x%x (nmsi %d)",
		    ddi_prop_exists(DDI_DEV_T_NONE, nxgep->dip,
		    DDI_PROP_CANSLEEP, "#msix-request"), nmsi));
		break;
	}

	NXGE_DEBUG_MSG((nxgep, MOD_CTL, "<==nxge_create_msi_property"));
	return (nmsi);
}
