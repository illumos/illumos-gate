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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * EHCI Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This module contains the main EHCI driver code which handles all USB
 * transfers, bandwidth allocations and other general functionalities.
 */

#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_isoch.h>
#include <sys/usb/hcd/ehci/ehci_xfer.h>

/*
 * EHCI MSI tunable:
 *
 * By default MSI is enabled on all supported platforms except for the
 * EHCI controller of ULI1575 South bridge.
 */
boolean_t ehci_enable_msi = B_TRUE;

/* Pointer to the state structure */
extern void *ehci_statep;

extern void ehci_handle_endpoint_reclaimation(ehci_state_t *);

extern uint_t ehci_vt62x2_workaround;
extern int force_ehci_off;

/* Adjustable variables for the size of the pools */
int ehci_qh_pool_size = EHCI_QH_POOL_SIZE;
int ehci_qtd_pool_size = EHCI_QTD_POOL_SIZE;

/*
 * Initialize the values which the order of 32ms intr qh are executed
 * by the host controller in the lattice tree.
 */
static uchar_t ehci_index[EHCI_NUM_INTR_QH_LISTS] =
	{0x00, 0x10, 0x08, 0x18,
	0x04, 0x14, 0x0c, 0x1c,
	0x02, 0x12, 0x0a, 0x1a,
	0x06, 0x16, 0x0e, 0x1e,
	0x01, 0x11, 0x09, 0x19,
	0x05, 0x15, 0x0d, 0x1d,
	0x03, 0x13, 0x0b, 0x1b,
	0x07, 0x17, 0x0f, 0x1f};

/*
 * Initialize the values which are used to calculate start split mask
 * for the low/full/high speed interrupt and isochronous endpoints.
 */
static uint_t ehci_start_split_mask[15] = {
		/*
		 * For high/full/low speed usb devices. For high speed
		 * device with polling interval greater than or equal
		 * to 8us (125us).
		 */
		0x01,	/* 00000001 */
		0x02,	/* 00000010 */
		0x04,	/* 00000100 */
		0x08,	/* 00001000 */
		0x10,	/* 00010000 */
		0x20,	/* 00100000 */
		0x40,	/* 01000000 */
		0x80,	/* 10000000 */

		/* Only for high speed devices with polling interval 4us */
		0x11,	/* 00010001 */
		0x22,	/* 00100010 */
		0x44,	/* 01000100 */
		0x88,	/* 10001000 */

		/* Only for high speed devices with polling interval 2us */
		0x55,	/* 01010101 */
		0xaa,	/* 10101010 */

		/* Only for high speed devices with polling interval 1us */
		0xff	/* 11111111 */
};

/*
 * Initialize the values which are used to calculate complete split mask
 * for the low/full speed interrupt and isochronous endpoints.
 */
static uint_t ehci_intr_complete_split_mask[7] = {
		/* Only full/low speed devices */
		0x1c,	/* 00011100 */
		0x38,	/* 00111000 */
		0x70,	/* 01110000 */
		0xe0,	/* 11100000 */
		0x00,	/* Need FSTN feature */
		0x00,	/* Need FSTN feature */
		0x00	/* Need FSTN feature */
};


/*
 * EHCI Internal Function Prototypes
 */

/* Host Controller Driver (HCD) initialization functions */
void		ehci_set_dma_attributes(ehci_state_t	*ehcip);
int		ehci_allocate_pools(ehci_state_t	*ehcip);
void		ehci_decode_ddi_dma_addr_bind_handle_result(
				ehci_state_t		*ehcip,
				int			result);
int		ehci_map_regs(ehci_state_t		*ehcip);
int		ehci_register_intrs_and_init_mutex(
				ehci_state_t		*ehcip);
static int	ehci_add_intrs(ehci_state_t		*ehcip,
				int			intr_type);
int		ehci_init_ctlr(ehci_state_t		*ehcip,
				int			init_type);
static int	ehci_take_control(ehci_state_t		*ehcip);
static int	ehci_init_periodic_frame_lst_table(
				ehci_state_t		*ehcip);
static void	ehci_build_interrupt_lattice(
				ehci_state_t		*ehcip);
usba_hcdi_ops_t *ehci_alloc_hcdi_ops(ehci_state_t	*ehcip);

/* Host Controller Driver (HCD) deinitialization functions */
int		ehci_cleanup(ehci_state_t		*ehcip);
static void	ehci_rem_intrs(ehci_state_t		*ehcip);
int		ehci_cpr_suspend(ehci_state_t		*ehcip);
int		ehci_cpr_resume(ehci_state_t		*ehcip);

/* Bandwidth Allocation functions */
int		ehci_allocate_bandwidth(ehci_state_t	*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			*pnode,
				uchar_t			*smask,
				uchar_t			*cmask);
static int	ehci_allocate_high_speed_bandwidth(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			*hnode,
				uchar_t			*smask,
				uchar_t			*cmask);
static int	ehci_allocate_classic_tt_bandwidth(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			pnode);
void		ehci_deallocate_bandwidth(ehci_state_t	*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			pnode,
				uchar_t			smask,
				uchar_t			cmask);
static void	ehci_deallocate_high_speed_bandwidth(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			hnode,
				uchar_t			smask,
				uchar_t			cmask);
static void	ehci_deallocate_classic_tt_bandwidth(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			pnode);
static int	ehci_compute_high_speed_bandwidth(
				ehci_state_t		*ehcip,
				usb_ep_descr_t		*endpoint,
				usb_port_status_t	port_status,
				uint_t			*sbandwidth,
				uint_t			*cbandwidth);
static int	ehci_compute_classic_bandwidth(
				usb_ep_descr_t		*endpoint,
				usb_port_status_t	port_status,
				uint_t			*bandwidth);
int		ehci_adjust_polling_interval(
				ehci_state_t		*ehcip,
				usb_ep_descr_t		*endpoint,
				usb_port_status_t	port_status);
static int	ehci_adjust_high_speed_polling_interval(
				ehci_state_t		*ehcip,
				usb_ep_descr_t		*endpoint);
static uint_t	ehci_lattice_height(uint_t		interval);
static uint_t	ehci_lattice_parent(uint_t		node);
static uint_t	ehci_find_periodic_node(
				uint_t			leaf,
				int			interval);
static uint_t	ehci_leftmost_leaf(uint_t		node,
				uint_t			height);
static uint_t	ehci_pow_2(uint_t x);
static uint_t	ehci_log_2(uint_t x);
static int	ehci_find_bestfit_hs_mask(
				ehci_state_t		*ehcip,
				uchar_t			*smask,
				uint_t			*pnode,
				usb_ep_descr_t		*endpoint,
				uint_t			bandwidth,
				int			interval);
static int	ehci_find_bestfit_ls_intr_mask(
				ehci_state_t		*ehcip,
				uchar_t			*smask,
				uchar_t			*cmask,
				uint_t			*pnode,
				uint_t			sbandwidth,
				uint_t			cbandwidth,
				int			interval);
static int	ehci_find_bestfit_sitd_in_mask(
				ehci_state_t		*ehcip,
				uchar_t			*smask,
				uchar_t			*cmask,
				uint_t			*pnode,
				uint_t			sbandwidth,
				uint_t			cbandwidth,
				int			interval);
static int	ehci_find_bestfit_sitd_out_mask(
				ehci_state_t		*ehcip,
				uchar_t			*smask,
				uint_t			*pnode,
				uint_t			sbandwidth,
				int			interval);
static uint_t	ehci_calculate_bw_availability_mask(
				ehci_state_t		*ehcip,
				uint_t			bandwidth,
				int			leaf,
				int			leaf_count,
				uchar_t			*bw_mask);
static void	ehci_update_bw_availability(
				ehci_state_t		*ehcip,
				int			bandwidth,
				int			leftmost_leaf,
				int			leaf_count,
				uchar_t			mask);

/* Miscellaneous functions */
ehci_state_t	*ehci_obtain_state(
				dev_info_t		*dip);
int		ehci_state_is_operational(
				ehci_state_t		*ehcip);
int		ehci_do_soft_reset(
				ehci_state_t		*ehcip);
usb_req_attrs_t ehci_get_xfer_attrs(ehci_state_t	*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
usb_frame_number_t ehci_get_current_frame_number(
				ehci_state_t		*ehcip);
static void	ehci_cpr_cleanup(
				ehci_state_t		*ehcip);
int		ehci_wait_for_sof(
				ehci_state_t		*ehcip);
void		ehci_toggle_scheduler(
				ehci_state_t		*ehcip);
void		ehci_print_caps(ehci_state_t		*ehcip);
void		ehci_print_regs(ehci_state_t		*ehcip);
void		ehci_print_qh(ehci_state_t		*ehcip,
				ehci_qh_t		*qh);
void		ehci_print_qtd(ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd);
void		ehci_create_stats(ehci_state_t		*ehcip);
void		ehci_destroy_stats(ehci_state_t		*ehcip);
void		ehci_do_intrs_stats(ehci_state_t	*ehcip,
				int		val);
void		ehci_do_byte_stats(ehci_state_t		*ehcip,
				size_t		len,
				uint8_t		attr,
				uint8_t		addr);

/*
 * check if this ehci controller can support PM
 */
int
ehci_hcdi_pm_support(dev_info_t *dip)
{
	ehci_state_t *ehcip = ddi_get_soft_state(ehci_statep,
	    ddi_get_instance(dip));

	if (((ehcip->ehci_vendor_id == PCI_VENDOR_NEC_COMBO) &&
	    (ehcip->ehci_device_id == PCI_DEVICE_NEC_COMBO)) ||

	    ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
	    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575)) ||

	    (ehcip->ehci_vendor_id == PCI_VENDOR_VIA)) {

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}

void
ehci_dma_attr_workaround(ehci_state_t	*ehcip)
{
	/*
	 * Some Nvidia chips can not handle qh dma address above 2G.
	 * The bit 31 of the dma address might be omitted and it will
	 * cause system crash or other unpredicable result. So force
	 * the dma address allocated below 2G to make ehci work.
	 */
	if (PCI_VENDOR_NVIDIA == ehcip->ehci_vendor_id) {
		switch (ehcip->ehci_device_id) {
			case PCI_DEVICE_NVIDIA_CK804:
			case PCI_DEVICE_NVIDIA_MCP04:
				USB_DPRINTF_L2(PRINT_MASK_ATTA,
				    ehcip->ehci_log_hdl,
				    "ehci_dma_attr_workaround: NVIDIA dma "
				    "workaround enabled, force dma address "
				    "to be allocated below 2G");
				ehcip->ehci_dma_attr.dma_attr_addr_hi =
				    0x7fffffffull;
				break;
			default:
				break;

		}
	}
}

/*
 * Host Controller Driver (HCD) initialization functions
 */

/*
 * ehci_set_dma_attributes:
 *
 * Set the limits in the DMA attributes structure. Most of the values used
 * in the  DMA limit structures are the default values as specified by	the
 * Writing PCI device drivers document.
 */
void
ehci_set_dma_attributes(ehci_state_t	*ehcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_set_dma_attributes:");

	/* Initialize the DMA attributes */
	ehcip->ehci_dma_attr.dma_attr_version = DMA_ATTR_V0;
	ehcip->ehci_dma_attr.dma_attr_addr_lo = 0x00000000ull;
	ehcip->ehci_dma_attr.dma_attr_addr_hi = 0xfffffffeull;

	/* 32 bit addressing */
	ehcip->ehci_dma_attr.dma_attr_count_max = EHCI_DMA_ATTR_COUNT_MAX;

	/* Byte alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	/*
	 * Since PCI  specification is byte alignment, the
	 * burst size field should be set to 1 for PCI devices.
	 */
	ehcip->ehci_dma_attr.dma_attr_burstsizes = 0x1;

	ehcip->ehci_dma_attr.dma_attr_minxfer = 0x1;
	ehcip->ehci_dma_attr.dma_attr_maxxfer = EHCI_DMA_ATTR_MAX_XFER;
	ehcip->ehci_dma_attr.dma_attr_seg = 0xffffffffull;
	ehcip->ehci_dma_attr.dma_attr_sgllen = 1;
	ehcip->ehci_dma_attr.dma_attr_granular = EHCI_DMA_ATTR_GRANULAR;
	ehcip->ehci_dma_attr.dma_attr_flags = 0;
	ehci_dma_attr_workaround(ehcip);
}


/*
 * ehci_allocate_pools:
 *
 * Allocate the system memory for the Endpoint Descriptor (QH) and for the
 * Transfer Descriptor (QTD) pools. Both QH and QTD structures must be aligned
 * to a 16 byte boundary.
 */
int
ehci_allocate_pools(ehci_state_t	*ehcip)
{
	ddi_device_acc_attr_t		dev_attr;
	size_t				real_length;
	int				result;
	uint_t				ccount;
	int				i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_allocate_pools:");

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version	= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder	= DDI_STRICTORDER_ACC;

	/* Byte alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_TD_QH_ALIGNMENT;

	/* Allocate the QTD pool DMA handle */
	if (ddi_dma_alloc_handle(ehcip->ehci_dip, &ehcip->ehci_dma_attr,
	    DDI_DMA_SLEEP, 0,
	    &ehcip->ehci_qtd_pool_dma_handle) != DDI_SUCCESS) {

		goto failure;
	}

	/* Allocate the memory for the QTD pool */
	if (ddi_dma_mem_alloc(ehcip->ehci_qtd_pool_dma_handle,
	    ehci_qtd_pool_size * sizeof (ehci_qtd_t),
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    0,
	    (caddr_t *)&ehcip->ehci_qtd_pool_addr,
	    &real_length,
	    &ehcip->ehci_qtd_pool_mem_handle)) {

		goto failure;
	}

	/* Map the QTD pool into the I/O address space */
	result = ddi_dma_addr_bind_handle(
	    ehcip->ehci_qtd_pool_dma_handle,
	    NULL,
	    (caddr_t)ehcip->ehci_qtd_pool_addr,
	    real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ehcip->ehci_qtd_pool_cookie,
	    &ccount);

	bzero((void *)ehcip->ehci_qtd_pool_addr,
	    ehci_qtd_pool_size * sizeof (ehci_qtd_t));

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_allocate_pools: More than 1 cookie");

		goto failure;
		}
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_allocate_pools: Result = %d", result);

		ehci_decode_ddi_dma_addr_bind_handle_result(ehcip, result);

		goto failure;
	}

	/*
	 * DMA addresses for QTD pools are bound
	 */
	ehcip->ehci_dma_addr_bind_flag |= EHCI_QTD_POOL_BOUND;

	/* Initialize the QTD pool */
	for (i = 0; i < ehci_qtd_pool_size; i ++) {
		Set_QTD(ehcip->ehci_qtd_pool_addr[i].
		    qtd_state, EHCI_QTD_FREE);
	}

	/* Allocate the QTD pool DMA handle */
	if (ddi_dma_alloc_handle(ehcip->ehci_dip,
	    &ehcip->ehci_dma_attr,
	    DDI_DMA_SLEEP,
	    0,
	    &ehcip->ehci_qh_pool_dma_handle) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_allocate_pools: ddi_dma_alloc_handle failed");

		goto failure;
	}

	/* Allocate the memory for the QH pool */
	if (ddi_dma_mem_alloc(ehcip->ehci_qh_pool_dma_handle,
	    ehci_qh_pool_size * sizeof (ehci_qh_t),
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    0,
	    (caddr_t *)&ehcip->ehci_qh_pool_addr,
	    &real_length,
	    &ehcip->ehci_qh_pool_mem_handle) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_allocate_pools: ddi_dma_mem_alloc failed");

		goto failure;
	}

	result = ddi_dma_addr_bind_handle(ehcip->ehci_qh_pool_dma_handle,
	    NULL,
	    (caddr_t)ehcip->ehci_qh_pool_addr,
	    real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ehcip->ehci_qh_pool_cookie,
	    &ccount);

	bzero((void *)ehcip->ehci_qh_pool_addr,
	    ehci_qh_pool_size * sizeof (ehci_qh_t));

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_allocate_pools: More than 1 cookie");

			goto failure;
		}
	} else {
		ehci_decode_ddi_dma_addr_bind_handle_result(ehcip, result);

		goto failure;
	}

	/*
	 * DMA addresses for QH pools are bound
	 */
	ehcip->ehci_dma_addr_bind_flag |= EHCI_QH_POOL_BOUND;

	/* Initialize the QH pool */
	for (i = 0; i < ehci_qh_pool_size; i ++) {
		Set_QH(ehcip->ehci_qh_pool_addr[i].qh_state, EHCI_QH_FREE);
	}

	/* Byte alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	return (DDI_SUCCESS);

failure:
	/* Byte alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	return (DDI_FAILURE);
}


/*
 * ehci_decode_ddi_dma_addr_bind_handle_result:
 *
 * Process the return values of ddi_dma_addr_bind_handle()
 */
void
ehci_decode_ddi_dma_addr_bind_handle_result(
	ehci_state_t	*ehcip,
	int		result)
{
	USB_DPRINTF_L2(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_decode_ddi_dma_addr_bind_handle_result:");

	switch (result) {
	case DDI_DMA_PARTIAL_MAP:
		USB_DPRINTF_L2(PRINT_MASK_ALL, ehcip->ehci_log_hdl,
		    "Partial transfers not allowed");
		break;
	case DDI_DMA_INUSE:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ehcip->ehci_log_hdl,
		    "Handle is in use");
		break;
	case DDI_DMA_NORESOURCES:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ehcip->ehci_log_hdl,
		    "No resources");
		break;
	case DDI_DMA_NOMAPPING:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ehcip->ehci_log_hdl,
		    "No mapping");
		break;
	case DDI_DMA_TOOBIG:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ehcip->ehci_log_hdl,
		    "Object is too big");
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ehcip->ehci_log_hdl,
		    "Unknown dma error");
	}
}


/*
 * ehci_map_regs:
 *
 * The Host Controller (HC) contains a set of on-chip operational registers
 * and which should be mapped into a non-cacheable portion of the  system
 * addressable space.
 */
int
ehci_map_regs(ehci_state_t	*ehcip)
{
	ddi_device_acc_attr_t	attr;
	uint16_t		cmd_reg;
	uint_t			length;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl, "ehci_map_regs:");

	/* Check to make sure we have memory access */
	if (pci_config_setup(ehcip->ehci_dip,
	    &ehcip->ehci_config_handle) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_map_regs: Config error");

		return (DDI_FAILURE);
	}

	/* Make sure Memory Access Enable is set */
	cmd_reg = pci_config_get16(ehcip->ehci_config_handle, PCI_CONF_COMM);

	if (!(cmd_reg & PCI_COMM_MAE)) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_map_regs: Memory base address access disabled");

		return (DDI_FAILURE);
	}

	/* The host controller will be little endian */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Map in EHCI Capability registers */
	if (ddi_regs_map_setup(ehcip->ehci_dip, 1,
	    (caddr_t *)&ehcip->ehci_capsp, 0,
	    sizeof (ehci_caps_t), &attr,
	    &ehcip->ehci_caps_handle) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_map_regs: Map setup error");

		return (DDI_FAILURE);
	}

	length = ddi_get8(ehcip->ehci_caps_handle,
	    (uint8_t *)&ehcip->ehci_capsp->ehci_caps_length);

	/* Free the original mapping */
	ddi_regs_map_free(&ehcip->ehci_caps_handle);

	/* Re-map in EHCI Capability and Operational registers */
	if (ddi_regs_map_setup(ehcip->ehci_dip, 1,
	    (caddr_t *)&ehcip->ehci_capsp, 0,
	    length + sizeof (ehci_regs_t), &attr,
	    &ehcip->ehci_caps_handle) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_map_regs: Map setup error");

		return (DDI_FAILURE);
	}

	/* Get the pointer to EHCI Operational Register */
	ehcip->ehci_regsp = (ehci_regs_t *)
	    ((uintptr_t)ehcip->ehci_capsp + length);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_map_regs: Capsp 0x%p Regsp 0x%p\n",
	    (void *)ehcip->ehci_capsp, (void *)ehcip->ehci_regsp);

	return (DDI_SUCCESS);
}

/*
 * The following simulated polling is for debugging purposes only.
 * It is activated on x86 by setting usb-polling=true in GRUB or ehci.conf.
 */
static int
ehci_is_polled(dev_info_t *dip)
{
	int ret;
	char *propval;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "usb-polling", &propval) != DDI_SUCCESS)

		return (0);

	ret = (strcmp(propval, "true") == 0);
	ddi_prop_free(propval);

	return (ret);
}

static void
ehci_poll_intr(void *arg)
{
	/* poll every msec */
	for (;;) {
		(void) ehci_intr(arg, NULL);
		delay(drv_usectohz(1000));
	}
}

/*
 * ehci_register_intrs_and_init_mutex:
 *
 * Register interrupts and initialize each mutex and condition variables
 */
int
ehci_register_intrs_and_init_mutex(ehci_state_t	*ehcip)
{
	int	intr_types;

#if defined(__x86)
	uint8_t iline;
#endif

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_register_intrs_and_init_mutex:");

	/*
	 * There is a known MSI hardware bug with the EHCI controller
	 * of ULI1575 southbridge. Hence MSI is disabled for this chip.
	 */
	if ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
	    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575)) {
		ehcip->ehci_msi_enabled = B_FALSE;
	} else {
		/* Set the MSI enable flag from the global EHCI MSI tunable */
		ehcip->ehci_msi_enabled = ehci_enable_msi;
	}

	/* launch polling thread instead of enabling pci interrupt */
	if (ehci_is_polled(ehcip->ehci_dip)) {
		extern pri_t maxclsyspri;

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_register_intrs_and_init_mutex: "
		    "running in simulated polled mode");

		(void) thread_create(NULL, 0, ehci_poll_intr, ehcip, 0, &p0,
		    TS_RUN, maxclsyspri);

		goto skip_intr;
	}

#if defined(__x86)
	/*
	 * Make sure that the interrupt pin is connected to the
	 * interrupt controller on x86.	 Interrupt line 255 means
	 * "unknown" or "not connected" (PCI spec 6.2.4, footnote 43).
	 * If we would return failure when interrupt line equals 255, then
	 * high speed devices will be routed to companion host controllers.
	 * However, it is not necessary to return failure here, and
	 * o/uhci codes don't check the interrupt line either.
	 * But it's good to log a message here for debug purposes.
	 */
	iline = pci_config_get8(ehcip->ehci_config_handle,
	    PCI_CONF_ILINE);

	if (iline == 255) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_register_intrs_and_init_mutex: "
		    "interrupt line value out of range (%d)",
		    iline);
	}
#endif	/* __x86 */

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(ehcip->ehci_dip,
	    &intr_types) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_register_intrs_and_init_mutex: "
		    "ddi_intr_get_supported_types failed");

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_register_intrs_and_init_mutex: "
	    "supported interrupt types 0x%x", intr_types);

	if ((intr_types & DDI_INTR_TYPE_MSI) && ehcip->ehci_msi_enabled) {
		if (ehci_add_intrs(ehcip, DDI_INTR_TYPE_MSI)
		    != DDI_SUCCESS) {
			USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_register_intrs_and_init_mutex: MSI "
			    "registration failed, trying FIXED interrupt \n");
		} else {
			USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_register_intrs_and_init_mutex: "
			    "Using MSI interrupt type\n");

			ehcip->ehci_intr_type = DDI_INTR_TYPE_MSI;
			ehcip->ehci_flags |= EHCI_INTR;
		}
	}

	if ((!(ehcip->ehci_flags & EHCI_INTR)) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		if (ehci_add_intrs(ehcip, DDI_INTR_TYPE_FIXED)
		    != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_register_intrs_and_init_mutex: "
			    "FIXED interrupt registration failed\n");

			return (DDI_FAILURE);
		}

		USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_register_intrs_and_init_mutex: "
		    "Using FIXED interrupt type\n");

		ehcip->ehci_intr_type = DDI_INTR_TYPE_FIXED;
		ehcip->ehci_flags |= EHCI_INTR;
	}

skip_intr:
	/* Create prototype for advance on async schedule */
	cv_init(&ehcip->ehci_async_schedule_advance_cv,
	    NULL, CV_DRIVER, NULL);

	return (DDI_SUCCESS);
}


/*
 * ehci_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
ehci_add_intrs(ehci_state_t *ehcip, int intr_type)
{
	int	actual, avail, intr_size, count = 0;
	int	i, flag, ret;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_add_intrs: interrupt type 0x%x", intr_type);

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(ehcip->ehci_dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: ddi_intr_get_nintrs() failure, "
		    "ret: %d, count: %d", ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(ehcip->ehci_dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: ddi_intr_get_navail() failure, "
		    "ret: %d, count: %d", ret, count);

		return (DDI_FAILURE);
	}

	if (avail < count) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: ehci_add_intrs: nintrs () "
		    "returned %d, navail returned %d\n", count, avail);
	}

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	ehcip->ehci_htable = kmem_zalloc(intr_size, KM_SLEEP);

	flag = (intr_type == DDI_INTR_TYPE_MSI) ?
	    DDI_INTR_ALLOC_STRICT:DDI_INTR_ALLOC_NORMAL;

	/* call ddi_intr_alloc() */
	ret = ddi_intr_alloc(ehcip->ehci_dip, ehcip->ehci_htable,
	    intr_type, 0, count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: ddi_intr_alloc() failed %d", ret);

		kmem_free(ehcip->ehci_htable, intr_size);

		return (DDI_FAILURE);
	}

	if (actual < count) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: Requested: %d, Received: %d\n",
		    count, actual);

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ehcip->ehci_htable[i]);

		kmem_free(ehcip->ehci_htable, intr_size);

		return (DDI_FAILURE);
	}

	ehcip->ehci_intr_cnt = actual;

	if ((ret = ddi_intr_get_pri(ehcip->ehci_htable[0],
	    &ehcip->ehci_intr_pri)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: ddi_intr_get_pri() failed %d", ret);

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ehcip->ehci_htable[i]);

		kmem_free(ehcip->ehci_htable, intr_size);

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_add_intrs: Supported Interrupt priority 0x%x",
	    ehcip->ehci_intr_pri);

	/* Test for high level mutex */
	if (ehcip->ehci_intr_pri >= ddi_intr_get_hilevel_pri()) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: Hi level interrupt not supported");

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ehcip->ehci_htable[i]);

		kmem_free(ehcip->ehci_htable, intr_size);

		return (DDI_FAILURE);
	}

	/* Initialize the mutex */
	mutex_init(&ehcip->ehci_int_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ehcip->ehci_intr_pri));

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(ehcip->ehci_htable[i],
		    ehci_intr, (caddr_t)ehcip,
		    (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_add_intrs:ddi_intr_add_handler() "
			    "failed %d", ret);

			for (i = 0; i < actual; i++)
				(void) ddi_intr_free(ehcip->ehci_htable[i]);

			mutex_destroy(&ehcip->ehci_int_mutex);
			kmem_free(ehcip->ehci_htable, intr_size);

			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(ehcip->ehci_htable[0],
	    &ehcip->ehci_intr_cap)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_add_intrs: ddi_intr_get_cap() failed %d", ret);

		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(ehcip->ehci_htable[i]);
			(void) ddi_intr_free(ehcip->ehci_htable[i]);
		}

		mutex_destroy(&ehcip->ehci_int_mutex);
		kmem_free(ehcip->ehci_htable, intr_size);

		return (DDI_FAILURE);
	}

	/* Enable all interrupts */
	if (ehcip->ehci_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(ehcip->ehci_htable,
		    ehcip->ehci_intr_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < ehcip->ehci_intr_cnt; i++)
			(void) ddi_intr_enable(ehcip->ehci_htable[i]);
	}

	return (DDI_SUCCESS);
}


/*
 * ehci_init_hardware
 *
 * take control from BIOS, reset EHCI host controller, and check version, etc.
 */
int
ehci_init_hardware(ehci_state_t	*ehcip)
{
	int			revision;
	uint16_t		cmd_reg;
	int			abort_on_BIOS_take_over_failure;

	/* Take control from the BIOS */
	if (ehci_take_control(ehcip) != USB_SUCCESS) {

		/* read .conf file properties */
		abort_on_BIOS_take_over_failure =
		    ddi_prop_get_int(DDI_DEV_T_ANY,
		    ehcip->ehci_dip, DDI_PROP_DONTPASS,
		    "abort-on-BIOS-take-over-failure", 0);

		if (abort_on_BIOS_take_over_failure) {

			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "Unable to take control from BIOS.");

			return (DDI_FAILURE);
		}

		USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "Unable to take control from BIOS. Failure is ignored.");
	}

	/* set Memory Master Enable */
	cmd_reg = pci_config_get16(ehcip->ehci_config_handle, PCI_CONF_COMM);
	cmd_reg |= (PCI_COMM_MAE | PCI_COMM_ME);
	pci_config_put16(ehcip->ehci_config_handle, PCI_CONF_COMM, cmd_reg);

	/* Reset the EHCI host controller */
	Set_OpReg(ehci_command,
	    Get_OpReg(ehci_command) | EHCI_CMD_HOST_CTRL_RESET);

	/* Wait 10ms for reset to complete */
	drv_usecwait(EHCI_RESET_TIMEWAIT);

	ASSERT(Get_OpReg(ehci_status) & EHCI_STS_HOST_CTRL_HALTED);

	/* Verify the version number */
	revision = Get_16Cap(ehci_version);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_init_hardware: Revision 0x%x", revision);

	/*
	 * EHCI driver supports EHCI host controllers compliant to
	 * 0.95 and higher revisions of EHCI specifications.
	 */
	if (revision < EHCI_REVISION_0_95) {

		USB_DPRINTF_L0(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "Revision 0x%x is not supported", revision);

		return (DDI_FAILURE);
	}

	if (ehcip->ehci_hc_soft_state == EHCI_CTLR_INIT_STATE) {

		/* Initialize the Frame list base address area */
		if (ehci_init_periodic_frame_lst_table(ehcip) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}

		/*
		 * For performance reasons, do not insert anything into the
		 * asynchronous list or activate the asynch list schedule until
		 * there is a valid QH.
		 */
		ehcip->ehci_head_of_async_sched_list = NULL;

		if ((ehcip->ehci_vendor_id == PCI_VENDOR_VIA) &&
		    (ehci_vt62x2_workaround & EHCI_VIA_ASYNC_SCHEDULE)) {
			/*
			 * The driver is unable to reliably stop the asynch
			 * list schedule on VIA VT6202 controllers, so we
			 * always keep a dummy QH on the list.
			 */
			ehci_qh_t *dummy_async_qh =
			    ehci_alloc_qh(ehcip, NULL, NULL);

			Set_QH(dummy_async_qh->qh_link_ptr,
			    ((ehci_qh_cpu_to_iommu(ehcip, dummy_async_qh) &
			    EHCI_QH_LINK_PTR) | EHCI_QH_LINK_REF_QH));

			/* Set this QH to be the "head" of the circular list */
			Set_QH(dummy_async_qh->qh_ctrl,
			    Get_QH(dummy_async_qh->qh_ctrl) |
			    EHCI_QH_CTRL_RECLAIM_HEAD);

			Set_QH(dummy_async_qh->qh_next_qtd,
			    EHCI_QH_NEXT_QTD_PTR_VALID);
			Set_QH(dummy_async_qh->qh_alt_next_qtd,
			    EHCI_QH_ALT_NEXT_QTD_PTR_VALID);

			ehcip->ehci_head_of_async_sched_list = dummy_async_qh;
			ehcip->ehci_open_async_count++;
			ehcip->ehci_async_req_count++;
		}
	}

	return (DDI_SUCCESS);
}


/*
 * ehci_init_workaround
 *
 * some workarounds during initializing ehci
 */
int
ehci_init_workaround(ehci_state_t	*ehcip)
{
	/*
	 * Acer Labs Inc. M5273 EHCI controller does not send
	 * interrupts unless the Root hub ports are routed to the EHCI
	 * host controller; so route the ports now, before we test for
	 * the presence of SOFs interrupts.
	 */
	if (ehcip->ehci_vendor_id == PCI_VENDOR_ALI) {
		/* Route all Root hub ports to EHCI host controller */
		Set_OpReg(ehci_config_flag, EHCI_CONFIG_FLAG_EHCI);
	}

	/*
	 * VIA chips have some issues and may not work reliably.
	 * Revisions >= 0x80 are part of a southbridge and appear
	 * to be reliable with the workaround.
	 * For revisions < 0x80, if we	were bound using class
	 * complain, else proceed. This will allow the user to
	 * bind ehci specifically to this chip and not have the
	 * warnings
	 */
	if (ehcip->ehci_vendor_id == PCI_VENDOR_VIA) {

		if (ehcip->ehci_rev_id >= PCI_VIA_REVISION_6212) {

			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_init_workaround: Applying VIA workarounds "
			    "for the 6212 chip.");

		} else if (strcmp(DEVI(ehcip->ehci_dip)->devi_binding_name,
		    "pciclass,0c0320") == 0) {

			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "Due to recently discovered incompatibilities");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "with this USB controller, USB2.x transfer");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "support has been disabled. This device will");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "continue to function as a USB1.x controller.");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "If you are interested in enabling USB2.x");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "support please, refer to the ehci(7D) man page.");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "Please also refer to www.sun.com/io for");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "Solaris Ready products and to");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "www.sun.com/bigadmin/hcl for additional");
			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "compatible USB products.");

			return (DDI_FAILURE);

			} else if (ehci_vt62x2_workaround) {

			USB_DPRINTF_L1(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "Applying VIA workarounds");
		}
	}

	return (DDI_SUCCESS);
}


/*
 * ehci_init_check_status
 *
 * Check if EHCI host controller is running
 */
int
ehci_init_check_status(ehci_state_t	*ehcip)
{
	clock_t			sof_time_wait;

	/*
	 * Get the number of clock ticks to wait.
	 * This is based on the maximum time it takes for a frame list rollover
	 * and maximum time wait for SOFs to begin.
	 */
	sof_time_wait = drv_usectohz((EHCI_NUM_PERIODIC_FRAME_LISTS * 1000) +
	    EHCI_SOF_TIMEWAIT);

	/* Tell the ISR to broadcast ehci_async_schedule_advance_cv */
	ehcip->ehci_flags |= EHCI_CV_INTR;

	/* We need to add a delay to allow the chip time to start running */
	(void) cv_reltimedwait(&ehcip->ehci_async_schedule_advance_cv,
	    &ehcip->ehci_int_mutex, sof_time_wait, TR_CLOCK_TICK);

	/*
	 * Check EHCI host controller is running, otherwise return failure.
	 */
	if ((ehcip->ehci_flags & EHCI_CV_INTR) ||
	    (Get_OpReg(ehci_status) & EHCI_STS_HOST_CTRL_HALTED)) {

		USB_DPRINTF_L0(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "No SOF interrupts have been received, this USB EHCI host"
		    "controller is unusable");

		/*
		 * Route all Root hub ports to Classic host
		 * controller, in case this is an unusable ALI M5273
		 * EHCI controller.
		 */
		if (ehcip->ehci_vendor_id == PCI_VENDOR_ALI) {
			Set_OpReg(ehci_config_flag, EHCI_CONFIG_FLAG_CLASSIC);
		}

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * ehci_init_ctlr:
 *
 * Initialize the Host Controller (HC).
 */
int
ehci_init_ctlr(ehci_state_t *ehcip, int init_type)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl, "ehci_init_ctlr:");

	if (init_type == EHCI_NORMAL_INITIALIZATION) {

		if (ehci_init_hardware(ehcip) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}

	/*
	 * Check for Asynchronous schedule park capability feature. If this
	 * feature is supported, then, program ehci command register with
	 * appropriate values..
	 */
	if (Get_Cap(ehci_hcc_params) & EHCI_HCC_ASYNC_SCHED_PARK_CAP) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_init_ctlr: Async park mode is supported");

		Set_OpReg(ehci_command, (Get_OpReg(ehci_command) |
		    (EHCI_CMD_ASYNC_PARK_ENABLE |
		    EHCI_CMD_ASYNC_PARK_COUNT_3)));
	}

	/*
	 * Check for programmable periodic frame list feature. If this
	 * feature is supported, then, program ehci command register with
	 * 1024 frame list value.
	 */
	if (Get_Cap(ehci_hcc_params) & EHCI_HCC_PROG_FRAME_LIST_FLAG) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_init_ctlr: Variable programmable periodic "
		    "frame list is supported");

		Set_OpReg(ehci_command, (Get_OpReg(ehci_command) |
		    EHCI_CMD_FRAME_1024_SIZE));
	}

	/*
	 * Currently EHCI driver doesn't support 64 bit addressing.
	 *
	 * If we are using 64 bit addressing capability, then, program
	 * ehci_ctrl_segment register with 4 Gigabyte segment where all
	 * of the interface data structures are allocated.
	 */
	if (Get_Cap(ehci_hcc_params) & EHCI_HCC_64BIT_ADDR_CAP) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_init_ctlr: EHCI driver doesn't support "
		    "64 bit addressing");
	}

	/* 64 bit addressing is not support */
	Set_OpReg(ehci_ctrl_segment, 0x00000000);

	/* Turn on/off the schedulers */
	ehci_toggle_scheduler(ehcip);

	/* Set host controller soft state to operational */
	ehcip->ehci_hc_soft_state = EHCI_CTLR_OPERATIONAL_STATE;

	/*
	 * Set the Periodic Frame List Base Address register with the
	 * starting physical address of the Periodic Frame List.
	 */
	Set_OpReg(ehci_periodic_list_base,
	    (uint32_t)(ehcip->ehci_pflt_cookie.dmac_address &
	    EHCI_PERIODIC_LIST_BASE));

	/*
	 * Set ehci_interrupt to enable all interrupts except Root
	 * Hub Status change interrupt.
	 */
	Set_OpReg(ehci_interrupt, EHCI_INTR_HOST_SYSTEM_ERROR |
	    EHCI_INTR_FRAME_LIST_ROLLOVER | EHCI_INTR_USB_ERROR |
	    EHCI_INTR_USB);

	/*
	 * Set the desired interrupt threshold and turn on EHCI host controller.
	 */
	Set_OpReg(ehci_command,
	    ((Get_OpReg(ehci_command) & ~EHCI_CMD_INTR_THRESHOLD) |
	    (EHCI_CMD_01_INTR | EHCI_CMD_HOST_CTRL_RUN)));

	ASSERT(Get_OpReg(ehci_command) & EHCI_CMD_HOST_CTRL_RUN);

	if (init_type == EHCI_NORMAL_INITIALIZATION) {

		if (ehci_init_workaround(ehcip) != DDI_SUCCESS) {

			/* Set host controller soft state to error */
			ehcip->ehci_hc_soft_state = EHCI_CTLR_ERROR_STATE;

			return (DDI_FAILURE);
		}

		if (ehci_init_check_status(ehcip) != DDI_SUCCESS) {

			/* Set host controller soft state to error */
			ehcip->ehci_hc_soft_state = EHCI_CTLR_ERROR_STATE;

			return (DDI_FAILURE);
		}

		USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_init_ctlr: SOF's have started");
	}

	/* Route all Root hub ports to EHCI host controller */
	Set_OpReg(ehci_config_flag, EHCI_CONFIG_FLAG_EHCI);

	return (DDI_SUCCESS);
}

/*
 * ehci_take_control:
 *
 * Handshake to take EHCI control from BIOS if necessary.  Its only valid for
 * x86 machines, because sparc doesn't have a BIOS.
 * On x86 machine, the take control process includes
 *    o get the base address of the extended capability list
 *    o find out the capability for handoff synchronization in the list.
 *    o check if BIOS has owned the host controller.
 *    o set the OS Owned semaphore bit, ask the BIOS to release the ownership.
 *    o wait for a constant time and check if BIOS has relinquished control.
 */
/* ARGSUSED */
static int
ehci_take_control(ehci_state_t *ehcip)
{
#if defined(__x86)
	uint32_t		extended_cap;
	uint32_t		extended_cap_offset;
	uint32_t		extended_cap_id;
	uint_t			retry;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_take_control:");

	/*
	 * According EHCI Spec 2.2.4, get EECP base address from HCCPARAMS
	 * register.
	 */
	extended_cap_offset = (Get_Cap(ehci_hcc_params) & EHCI_HCC_EECP) >>
	    EHCI_HCC_EECP_SHIFT;

	/*
	 * According EHCI Spec 2.2.4, if the extended capability offset is
	 * less than 40h then its not valid.  This means we don't need to
	 * worry about BIOS handoff.
	 */
	if (extended_cap_offset < EHCI_HCC_EECP_MIN_OFFSET) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_take_control: Hardware doesn't support legacy.");

		goto success;
	}

	/*
	 * According EHCI Spec 2.1.7, A zero offset indicates the
	 * end of the extended capability list.
	 */
	while (extended_cap_offset) {

		/* Get the extended capability value. */
		extended_cap = pci_config_get32(ehcip->ehci_config_handle,
		    extended_cap_offset);

		/*
		 * It's possible that we'll receive an invalid PCI read here due
		 * to something going wrong due to platform firmware. This has
		 * been observed in the wild depending on the version of ACPI in
		 * use. If this happens, we'll assume that the capability does
		 * not exist and that we do not need to take control from the
		 * BIOS.
		 */
		if (extended_cap == PCI_EINVAL32) {
			extended_cap_id = EHCI_EX_CAP_ID_RESERVED;
			break;
		}

		/* Get the capability ID */
		extended_cap_id = (extended_cap & EHCI_EX_CAP_ID) >>
		    EHCI_EX_CAP_ID_SHIFT;

		/* Check if the card support legacy */
		if (extended_cap_id == EHCI_EX_CAP_ID_BIOS_HANDOFF) {
			break;
		}

		/* Get the offset of the next capability */
		extended_cap_offset = (extended_cap & EHCI_EX_CAP_NEXT_PTR) >>
		    EHCI_EX_CAP_NEXT_PTR_SHIFT;

	}

	/*
	 * Unable to find legacy support in hardware's extended capability list.
	 * This means we don't need to worry about BIOS handoff.
	 */
	if (extended_cap_id != EHCI_EX_CAP_ID_BIOS_HANDOFF) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_take_control: Hardware doesn't support legacy");

		goto success;
	}

	/* Check if BIOS has owned it. */
	if (!(extended_cap & EHCI_LEGSUP_BIOS_OWNED_SEM)) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_take_control: BIOS does not own EHCI");

		goto success;
	}

	/*
	 * According EHCI Spec 5.1, The OS driver initiates an ownership
	 * request by setting the OS Owned semaphore to a one. The OS
	 * waits for the BIOS Owned bit to go to a zero before attempting
	 * to use the EHCI controller. The time that OS must wait for BIOS
	 * to respond to the request for ownership is beyond the scope of
	 * this specification.
	 * It waits up to EHCI_TAKEOVER_WAIT_COUNT*EHCI_TAKEOVER_DELAY ms
	 * for BIOS to release the ownership.
	 */
	extended_cap |= EHCI_LEGSUP_OS_OWNED_SEM;
	pci_config_put32(ehcip->ehci_config_handle, extended_cap_offset,
	    extended_cap);

	for (retry = 0; retry < EHCI_TAKEOVER_WAIT_COUNT; retry++) {

		/* wait a special interval */
#ifndef __lock_lint
		delay(drv_usectohz(EHCI_TAKEOVER_DELAY));
#endif
		/* Check to see if the BIOS has released the ownership */
		extended_cap = pci_config_get32(
		    ehcip->ehci_config_handle, extended_cap_offset);

		if (!(extended_cap & EHCI_LEGSUP_BIOS_OWNED_SEM)) {

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    ehcip->ehci_log_hdl,
			    "ehci_take_control: BIOS has released "
			    "the ownership. retry = %d", retry);

			goto success;
		}

	}

	USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_take_control: take control from BIOS failed.");

	return (USB_FAILURE);

success:

#endif	/* __x86 */
	return (USB_SUCCESS);
}


/*
 * ehci_init_periodic_frame_list_table :
 *
 * Allocate the system memory and initialize Host Controller
 * Periodic Frame List table area. The starting of the Periodic
 * Frame List Table area must be 4096 byte aligned.
 */
static int
ehci_init_periodic_frame_lst_table(ehci_state_t *ehcip)
{
	ddi_device_acc_attr_t	dev_attr;
	size_t			real_length;
	uint_t			ccount;
	int			result;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_init_periodic_frame_lst_table:");

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Force the required 4K restrictive alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_PFL_ALIGNMENT;

	/* Create space for the Periodic Frame List */
	if (ddi_dma_alloc_handle(ehcip->ehci_dip, &ehcip->ehci_dma_attr,
	    DDI_DMA_SLEEP, 0, &ehcip->ehci_pflt_dma_handle) != DDI_SUCCESS) {

		goto failure;
	}

	if (ddi_dma_mem_alloc(ehcip->ehci_pflt_dma_handle,
	    sizeof (ehci_periodic_frame_list_t),
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    0, (caddr_t *)&ehcip->ehci_periodic_frame_list_tablep,
	    &real_length, &ehcip->ehci_pflt_mem_handle)) {

		goto failure;
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_init_periodic_frame_lst_table: "
	    "Real length %lu", real_length);

	/* Map the whole Periodic Frame List into the I/O address space */
	result = ddi_dma_addr_bind_handle(ehcip->ehci_pflt_dma_handle,
	    NULL, (caddr_t)ehcip->ehci_periodic_frame_list_tablep,
	    real_length, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &ehcip->ehci_pflt_cookie, &ccount);

	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_init_periodic_frame_lst_table: "
			    "More than 1 cookie");

			goto failure;
		}
	} else {
		ehci_decode_ddi_dma_addr_bind_handle_result(ehcip, result);

		goto failure;
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_init_periodic_frame_lst_table: virtual 0x%p physical 0x%x",
	    (void *)ehcip->ehci_periodic_frame_list_tablep,
	    ehcip->ehci_pflt_cookie.dmac_address);

	/*
	 * DMA addresses for Periodic Frame List are bound.
	 */
	ehcip->ehci_dma_addr_bind_flag |= EHCI_PFLT_DMA_BOUND;

	bzero((void *)ehcip->ehci_periodic_frame_list_tablep, real_length);

	/* Initialize the Periodic Frame List */
	ehci_build_interrupt_lattice(ehcip);

	/* Reset Byte Alignment to Default */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	return (DDI_SUCCESS);
failure:
	/* Byte alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	return (DDI_FAILURE);
}


/*
 * ehci_build_interrupt_lattice:
 *
 * Construct the interrupt lattice tree using static Endpoint Descriptors
 * (QH). This interrupt lattice tree will have total of 32 interrupt  QH
 * lists and the Host Controller (HC) processes one interrupt QH list in
 * every frame. The Host Controller traverses the periodic schedule by
 * constructing an array offset reference from the Periodic List Base Address
 * register and bits 12 to 3 of Frame Index register. It fetches the element
 * and begins traversing the graph of linked schedule data structures.
 */
static void
ehci_build_interrupt_lattice(ehci_state_t	*ehcip)
{
	ehci_qh_t	*list_array = ehcip->ehci_qh_pool_addr;
	ushort_t	ehci_index[EHCI_NUM_PERIODIC_FRAME_LISTS];
	ehci_periodic_frame_list_t *periodic_frame_list =
	    ehcip->ehci_periodic_frame_list_tablep;
	ushort_t	*temp, num_of_nodes;
	uintptr_t	addr;
	int		i, j, k;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_build_interrupt_lattice:");

	/*
	 * Reserve the first 63 Endpoint Descriptor (QH) structures
	 * in the pool as static endpoints & these are required for
	 * constructing interrupt lattice tree.
	 */
	for (i = 0; i < EHCI_NUM_STATIC_NODES; i++) {
		Set_QH(list_array[i].qh_state, EHCI_QH_STATIC);
		Set_QH(list_array[i].qh_status, EHCI_QH_STS_HALTED);
		Set_QH(list_array[i].qh_next_qtd, EHCI_QH_NEXT_QTD_PTR_VALID);
		Set_QH(list_array[i].qh_alt_next_qtd,
		    EHCI_QH_ALT_NEXT_QTD_PTR_VALID);
	}

	/*
	 * Make sure that last Endpoint on the periodic frame list terminates
	 * periodic schedule.
	 */
	Set_QH(list_array[0].qh_link_ptr, EHCI_QH_LINK_PTR_VALID);

	/* Build the interrupt lattice tree */
	for (i = 0; i < (EHCI_NUM_STATIC_NODES / 2); i++) {
		/*
		 * The next  pointer in the host controller  endpoint
		 * descriptor must contain an iommu address. Calculate
		 * the offset into the cpu address and add this to the
		 * starting iommu address.
		 */
		addr = ehci_qh_cpu_to_iommu(ehcip, (ehci_qh_t *)&list_array[i]);

		Set_QH(list_array[2*i + 1].qh_link_ptr,
		    addr | EHCI_QH_LINK_REF_QH);
		Set_QH(list_array[2*i + 2].qh_link_ptr,
		    addr | EHCI_QH_LINK_REF_QH);
	}

	/* Build the tree bottom */
	temp = (unsigned short *)
	    kmem_zalloc(EHCI_NUM_PERIODIC_FRAME_LISTS * 2, KM_SLEEP);

	num_of_nodes = 1;

	/*
	 * Initialize the values which are used for setting up head pointers
	 * for the 32ms scheduling lists which starts from the Periodic Frame
	 * List.
	 */
	for (i = 0; i < ehci_log_2(EHCI_NUM_PERIODIC_FRAME_LISTS); i++) {
		for (j = 0, k = 0; k < num_of_nodes; k++, j++) {
			ehci_index[j++] = temp[k];
			ehci_index[j]	= temp[k] + ehci_pow_2(i);
		}

		num_of_nodes *= 2;
		for (k = 0; k < num_of_nodes; k++)
			temp[k] = ehci_index[k];
	}

	kmem_free((void *)temp, (EHCI_NUM_PERIODIC_FRAME_LISTS * 2));

	/*
	 * Initialize the interrupt list in the Periodic Frame List Table
	 * so that it points to the bottom of the tree.
	 */
	for (i = 0, j = 0; i < ehci_pow_2(TREE_HEIGHT); i++) {
		addr = ehci_qh_cpu_to_iommu(ehcip, (ehci_qh_t *)
		    (&list_array[((EHCI_NUM_STATIC_NODES + 1) / 2) + i - 1]));

		ASSERT(addr);

		for (k = 0; k < ehci_pow_2(TREE_HEIGHT); k++) {
			Set_PFLT(periodic_frame_list->
			    ehci_periodic_frame_list_table[ehci_index[j++]],
			    (uint32_t)(addr | EHCI_QH_LINK_REF_QH));
		}
	}
}


/*
 * ehci_alloc_hcdi_ops:
 *
 * The HCDI interfaces or entry points are the software interfaces used by
 * the Universal Serial Bus Driver  (USBA) to  access the services of the
 * Host Controller Driver (HCD).  During HCD initialization, inform  USBA
 * about all available HCDI interfaces or entry points.
 */
usba_hcdi_ops_t *
ehci_alloc_hcdi_ops(ehci_state_t	*ehcip)
{
	usba_hcdi_ops_t			*usba_hcdi_ops;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_alloc_hcdi_ops:");

	usba_hcdi_ops = usba_alloc_hcdi_ops();

	usba_hcdi_ops->usba_hcdi_ops_version = HCDI_OPS_VERSION;

	usba_hcdi_ops->usba_hcdi_pm_support = ehci_hcdi_pm_support;
	usba_hcdi_ops->usba_hcdi_pipe_open = ehci_hcdi_pipe_open;
	usba_hcdi_ops->usba_hcdi_pipe_close = ehci_hcdi_pipe_close;

	usba_hcdi_ops->usba_hcdi_pipe_reset = ehci_hcdi_pipe_reset;
	usba_hcdi_ops->usba_hcdi_pipe_reset_data_toggle =
	    ehci_hcdi_pipe_reset_data_toggle;

	usba_hcdi_ops->usba_hcdi_pipe_ctrl_xfer = ehci_hcdi_pipe_ctrl_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_bulk_xfer = ehci_hcdi_pipe_bulk_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_intr_xfer = ehci_hcdi_pipe_intr_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_isoc_xfer = ehci_hcdi_pipe_isoc_xfer;

	usba_hcdi_ops->usba_hcdi_bulk_transfer_size =
	    ehci_hcdi_bulk_transfer_size;

	usba_hcdi_ops->usba_hcdi_pipe_stop_intr_polling =
	    ehci_hcdi_pipe_stop_intr_polling;
	usba_hcdi_ops->usba_hcdi_pipe_stop_isoc_polling =
	    ehci_hcdi_pipe_stop_isoc_polling;

	usba_hcdi_ops->usba_hcdi_get_current_frame_number =
	    ehci_hcdi_get_current_frame_number;
	usba_hcdi_ops->usba_hcdi_get_max_isoc_pkts =
	    ehci_hcdi_get_max_isoc_pkts;

	usba_hcdi_ops->usba_hcdi_console_input_init =
	    ehci_hcdi_polled_input_init;
	usba_hcdi_ops->usba_hcdi_console_input_enter =
	    ehci_hcdi_polled_input_enter;
	usba_hcdi_ops->usba_hcdi_console_read =
	    ehci_hcdi_polled_read;
	usba_hcdi_ops->usba_hcdi_console_input_exit =
	    ehci_hcdi_polled_input_exit;
	usba_hcdi_ops->usba_hcdi_console_input_fini =
	    ehci_hcdi_polled_input_fini;

	usba_hcdi_ops->usba_hcdi_console_output_init =
	    ehci_hcdi_polled_output_init;
	usba_hcdi_ops->usba_hcdi_console_output_enter =
	    ehci_hcdi_polled_output_enter;
	usba_hcdi_ops->usba_hcdi_console_write =
	    ehci_hcdi_polled_write;
	usba_hcdi_ops->usba_hcdi_console_output_exit =
	    ehci_hcdi_polled_output_exit;
	usba_hcdi_ops->usba_hcdi_console_output_fini =
	    ehci_hcdi_polled_output_fini;
	return (usba_hcdi_ops);
}


/*
 * Host Controller Driver (HCD) deinitialization functions
 */

/*
 * ehci_cleanup:
 *
 * Cleanup on attach failure or detach
 */
int
ehci_cleanup(ehci_state_t	*ehcip)
{
	ehci_trans_wrapper_t	*tw;
	ehci_pipe_private_t	*pp;
	ehci_qtd_t		*qtd;
	int			i, ctrl, rval;
	int			flags = ehcip->ehci_flags;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl, "ehci_cleanup:");

	if (flags & EHCI_RHREG) {
		/* Unload the root hub driver */
		if (ehci_unload_root_hub_driver(ehcip) != USB_SUCCESS) {

			return (DDI_FAILURE);
		}
	}

	if (flags & EHCI_USBAREG) {
		/* Unregister this HCD instance with USBA */
		usba_hcdi_unregister(ehcip->ehci_dip);
	}

	if (flags & EHCI_INTR) {

		mutex_enter(&ehcip->ehci_int_mutex);

		/* Disable all EHCI QH list processing */
		Set_OpReg(ehci_command, (Get_OpReg(ehci_command) &
		    ~(EHCI_CMD_ASYNC_SCHED_ENABLE |
		    EHCI_CMD_PERIODIC_SCHED_ENABLE)));

		/* Disable all EHCI interrupts */
		Set_OpReg(ehci_interrupt, 0);

		/* wait for the next SOF */
		(void) ehci_wait_for_sof(ehcip);

		/* Route all Root hub ports to Classic host controller */
		Set_OpReg(ehci_config_flag, EHCI_CONFIG_FLAG_CLASSIC);

		/* Stop the EHCI host controller */
		Set_OpReg(ehci_command,
		    Get_OpReg(ehci_command) & ~EHCI_CMD_HOST_CTRL_RUN);

		mutex_exit(&ehcip->ehci_int_mutex);

		/* Wait for sometime */
		delay(drv_usectohz(EHCI_TIMEWAIT));

		ehci_rem_intrs(ehcip);
	}

	/* Unmap the EHCI registers */
	if (ehcip->ehci_caps_handle) {
		ddi_regs_map_free(&ehcip->ehci_caps_handle);
	}

	if (ehcip->ehci_config_handle) {
		pci_config_teardown(&ehcip->ehci_config_handle);
	}

	/* Free all the buffers */
	if (ehcip->ehci_qtd_pool_addr && ehcip->ehci_qtd_pool_mem_handle) {
		for (i = 0; i < ehci_qtd_pool_size; i ++) {
			qtd = &ehcip->ehci_qtd_pool_addr[i];
			ctrl = Get_QTD(ehcip->
			    ehci_qtd_pool_addr[i].qtd_state);

			if ((ctrl != EHCI_QTD_FREE) &&
			    (ctrl != EHCI_QTD_DUMMY) &&
			    (qtd->qtd_trans_wrapper)) {

				mutex_enter(&ehcip->ehci_int_mutex);

				tw = (ehci_trans_wrapper_t *)
				    EHCI_LOOKUP_ID((uint32_t)
				    Get_QTD(qtd->qtd_trans_wrapper));

				/* Obtain the pipe private structure */
				pp = tw->tw_pipe_private;

				/* Stop the the transfer timer */
				ehci_stop_xfer_timer(ehcip, tw,
				    EHCI_REMOVE_XFER_ALWAYS);

				ehci_deallocate_tw(ehcip, pp, tw);

				mutex_exit(&ehcip->ehci_int_mutex);
			}
		}

		/*
		 * If EHCI_QTD_POOL_BOUND flag is set, then unbind
		 * the handle for QTD pools.
		 */
		if ((ehcip->ehci_dma_addr_bind_flag &
		    EHCI_QTD_POOL_BOUND) == EHCI_QTD_POOL_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ehcip->ehci_qtd_pool_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}
		ddi_dma_mem_free(&ehcip->ehci_qtd_pool_mem_handle);
	}

	/* Free the QTD pool */
	if (ehcip->ehci_qtd_pool_dma_handle) {
		ddi_dma_free_handle(&ehcip->ehci_qtd_pool_dma_handle);
	}

	if (ehcip->ehci_qh_pool_addr && ehcip->ehci_qh_pool_mem_handle) {
		/*
		 * If EHCI_QH_POOL_BOUND flag is set, then unbind
		 * the handle for QH pools.
		 */
		if ((ehcip->ehci_dma_addr_bind_flag &
		    EHCI_QH_POOL_BOUND) == EHCI_QH_POOL_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ehcip->ehci_qh_pool_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}

		ddi_dma_mem_free(&ehcip->ehci_qh_pool_mem_handle);
	}

	/* Free the QH pool */
	if (ehcip->ehci_qh_pool_dma_handle) {
		ddi_dma_free_handle(&ehcip->ehci_qh_pool_dma_handle);
	}

	/* Free the Periodic frame list table (PFLT) area */
	if (ehcip->ehci_periodic_frame_list_tablep &&
	    ehcip->ehci_pflt_mem_handle) {
		/*
		 * If EHCI_PFLT_DMA_BOUND flag is set, then unbind
		 * the handle for PFLT.
		 */
		if ((ehcip->ehci_dma_addr_bind_flag &
		    EHCI_PFLT_DMA_BOUND) == EHCI_PFLT_DMA_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ehcip->ehci_pflt_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}

		ddi_dma_mem_free(&ehcip->ehci_pflt_mem_handle);
	}

	(void) ehci_isoc_cleanup(ehcip);

	if (ehcip->ehci_pflt_dma_handle) {
		ddi_dma_free_handle(&ehcip->ehci_pflt_dma_handle);
	}

	if (flags & EHCI_INTR) {
		/* Destroy the mutex */
		mutex_destroy(&ehcip->ehci_int_mutex);

		/* Destroy the async schedule advance condition variable */
		cv_destroy(&ehcip->ehci_async_schedule_advance_cv);
	}

	/* clean up kstat structs */
	ehci_destroy_stats(ehcip);

	/* Free ehci hcdi ops */
	if (ehcip->ehci_hcdi_ops) {
		usba_free_hcdi_ops(ehcip->ehci_hcdi_ops);
	}

	if (flags & EHCI_ZALLOC) {

		usb_free_log_hdl(ehcip->ehci_log_hdl);

		/* Remove all properties that might have been created */
		ddi_prop_remove_all(ehcip->ehci_dip);

		/* Free the soft state */
		ddi_soft_state_free(ehci_statep,
		    ddi_get_instance(ehcip->ehci_dip));
	}

	return (DDI_SUCCESS);
}


/*
 * ehci_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
ehci_rem_intrs(ehci_state_t	*ehcip)
{
	int	i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_rem_intrs: interrupt type 0x%x", ehcip->ehci_intr_type);

	/* Disable all interrupts */
	if (ehcip->ehci_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(ehcip->ehci_htable,
		    ehcip->ehci_intr_cnt);
	} else {
		for (i = 0; i < ehcip->ehci_intr_cnt; i++) {
			(void) ddi_intr_disable(ehcip->ehci_htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < ehcip->ehci_intr_cnt; i++) {
		(void) ddi_intr_remove_handler(ehcip->ehci_htable[i]);
		(void) ddi_intr_free(ehcip->ehci_htable[i]);
	}

	kmem_free(ehcip->ehci_htable,
	    ehcip->ehci_intr_cnt * sizeof (ddi_intr_handle_t));
}


/*
 * ehci_cpr_suspend
 */
int
ehci_cpr_suspend(ehci_state_t	*ehcip)
{
	int	i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_cpr_suspend:");

	/* Call into the root hub and suspend it */
	if (usba_hubdi_detach(ehcip->ehci_dip, DDI_SUSPEND) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_cpr_suspend: root hub fails to suspend");

		return (DDI_FAILURE);
	}

	/* Only root hub's intr pipe should be open at this time */
	mutex_enter(&ehcip->ehci_int_mutex);

	ASSERT(ehcip->ehci_open_pipe_count == 0);

	/* Just wait till all resources are reclaimed */
	i = 0;
	while ((ehcip->ehci_reclaim_list != NULL) && (i++ < 3)) {
		ehci_handle_endpoint_reclaimation(ehcip);
		(void) ehci_wait_for_sof(ehcip);
	}
	ASSERT(ehcip->ehci_reclaim_list == NULL);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_cpr_suspend: Disable HC QH list processing");

	/* Disable all EHCI QH list processing */
	Set_OpReg(ehci_command, (Get_OpReg(ehci_command) &
	    ~(EHCI_CMD_ASYNC_SCHED_ENABLE | EHCI_CMD_PERIODIC_SCHED_ENABLE)));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_cpr_suspend: Disable HC interrupts");

	/* Disable all EHCI interrupts */
	Set_OpReg(ehci_interrupt, 0);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_cpr_suspend: Wait for the next SOF");

	/* Wait for the next SOF */
	if (ehci_wait_for_sof(ehcip) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_cpr_suspend: ehci host controller suspend failed");

		mutex_exit(&ehcip->ehci_int_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * Stop the ehci host controller
	 * if usb keyboard is not connected.
	 */
	if (ehcip->ehci_polled_kbd_count == 0 || force_ehci_off != 0) {
		Set_OpReg(ehci_command,
		    Get_OpReg(ehci_command) & ~EHCI_CMD_HOST_CTRL_RUN);

	}

	/* Set host controller soft state to suspend */
	ehcip->ehci_hc_soft_state = EHCI_CTLR_SUSPEND_STATE;

	mutex_exit(&ehcip->ehci_int_mutex);

	return (DDI_SUCCESS);
}


/*
 * ehci_cpr_resume
 */
int
ehci_cpr_resume(ehci_state_t	*ehcip)
{
	mutex_enter(&ehcip->ehci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_cpr_resume: Restart the controller");

	/* Cleanup ehci specific information across cpr */
	ehci_cpr_cleanup(ehcip);

	/* Restart the controller */
	if (ehci_init_ctlr(ehcip, EHCI_NORMAL_INITIALIZATION) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_cpr_resume: ehci host controller resume failed ");

		mutex_exit(&ehcip->ehci_int_mutex);

		return (DDI_FAILURE);
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	/* Now resume the root hub */
	if (usba_hubdi_attach(ehcip->ehci_dip, DDI_RESUME) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * Bandwidth Allocation functions
 */

/*
 * ehci_allocate_bandwidth:
 *
 * Figure out whether or not this interval may be supported. Return the index
 * into the  lattice if it can be supported.  Return allocation failure if it
 * can not be supported.
 */
int
ehci_allocate_bandwidth(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			*pnode,
	uchar_t			*smask,
	uchar_t			*cmask)
{
	int			error = USB_SUCCESS;

	/* This routine is protected by the ehci_int_mutex */
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Reset the pnode to the last checked pnode */
	*pnode = 0;

	/* Allocate high speed bandwidth */
	if ((error = ehci_allocate_high_speed_bandwidth(ehcip,
	    ph, pnode, smask, cmask)) != USB_SUCCESS) {

		return (error);
	}

	/*
	 * For low/full speed usb devices, allocate classic TT bandwidth
	 * in additional to high speed bandwidth.
	 */
	if (ph->p_usba_device->usb_port_status != USBA_HIGH_SPEED_DEV) {

		/* Allocate classic TT bandwidth */
		if ((error = ehci_allocate_classic_tt_bandwidth(
		    ehcip, ph, *pnode)) != USB_SUCCESS) {

			/* Deallocate high speed bandwidth */
			ehci_deallocate_high_speed_bandwidth(
			    ehcip, ph, *pnode, *smask, *cmask);
		}
	}

	return (error);
}


/*
 * ehci_allocate_high_speed_bandwidth:
 *
 * Allocate high speed bandwidth for the low/full/high speed interrupt and
 * isochronous endpoints.
 */
static int
ehci_allocate_high_speed_bandwidth(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			*pnode,
	uchar_t			*smask,
	uchar_t			*cmask)
{
	uint_t			sbandwidth, cbandwidth;
	int			interval;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	usba_device_t		*child_ud;
	usb_port_status_t	port_status;
	int			error;

	/* This routine is protected by the ehci_int_mutex */
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get child's usba device structure */
	child_ud = ph->p_usba_device;

	mutex_enter(&child_ud->usb_mutex);

	/* Get the current usb device's port status */
	port_status = ph->p_usba_device->usb_port_status;

	mutex_exit(&child_ud->usb_mutex);

	/*
	 * Calculate the length in bytes of a transaction on this
	 * periodic endpoint. Return failure if maximum packet is
	 * zero.
	 */
	error = ehci_compute_high_speed_bandwidth(ehcip, endpoint,
	    port_status, &sbandwidth, &cbandwidth);
	if (error != USB_SUCCESS) {

		return (error);
	}

	/*
	 * Adjust polling interval to be a power of 2.
	 * If this interval can't be supported, return
	 * allocation failure.
	 */
	interval = ehci_adjust_polling_interval(ehcip, endpoint, port_status);
	if (interval == USB_FAILURE) {

		return (USB_FAILURE);
	}

	if (port_status == USBA_HIGH_SPEED_DEV) {
		/* Allocate bandwidth for high speed devices */
		if ((endpoint->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_ISOCH) {
			error = USB_SUCCESS;
		} else {

			error = ehci_find_bestfit_hs_mask(ehcip, smask, pnode,
			    endpoint, sbandwidth, interval);
		}

		*cmask = 0x00;

	} else {
		if ((endpoint->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_INTR) {

			/* Allocate bandwidth for low speed interrupt */
			error = ehci_find_bestfit_ls_intr_mask(ehcip,
			    smask, cmask, pnode, sbandwidth, cbandwidth,
			    interval);
		} else {
			if ((endpoint->bEndpointAddress &
			    USB_EP_DIR_MASK) == USB_EP_DIR_IN) {

				/* Allocate bandwidth for sitd in */
				error = ehci_find_bestfit_sitd_in_mask(ehcip,
				    smask, cmask, pnode, sbandwidth, cbandwidth,
				    interval);
			} else {

				/* Allocate bandwidth for sitd out */
				error = ehci_find_bestfit_sitd_out_mask(ehcip,
				    smask, pnode, sbandwidth, interval);
				*cmask = 0x00;
			}
		}
	}

	if (error != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_BW, ehcip->ehci_log_hdl,
		    "ehci_allocate_high_speed_bandwidth: Reached maximum "
		    "bandwidth value and cannot allocate bandwidth for a "
		    "given high-speed periodic endpoint");

		return (USB_NO_BANDWIDTH);
	}

	return (error);
}


/*
 * ehci_allocate_classic_tt_speed_bandwidth:
 *
 * Allocate classic TT bandwidth for the low/full speed interrupt and
 * isochronous endpoints.
 */
static int
ehci_allocate_classic_tt_bandwidth(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			pnode)
{
	uint_t			bandwidth, min;
	uint_t			height, leftmost, list;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	usba_device_t		*child_ud, *parent_ud;
	usb_port_status_t	port_status;
	int			i, interval;

	/* This routine is protected by the ehci_int_mutex */
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get child's usba device structure */
	child_ud = ph->p_usba_device;

	mutex_enter(&child_ud->usb_mutex);

	/* Get the current usb device's port status */
	port_status = child_ud->usb_port_status;

	/* Get the parent high speed hub's usba device structure */
	parent_ud = child_ud->usb_hs_hub_usba_dev;

	mutex_exit(&child_ud->usb_mutex);

	USB_DPRINTF_L3(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_allocate_classic_tt_bandwidth: "
	    "child_ud 0x%p parent_ud 0x%p",
	    (void *)child_ud, (void *)parent_ud);

	/*
	 * Calculate the length in bytes of a transaction on this
	 * periodic endpoint. Return failure if maximum packet is
	 * zero.
	 */
	if (ehci_compute_classic_bandwidth(endpoint,
	    port_status, &bandwidth) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_BW, ehcip->ehci_log_hdl,
		    "ehci_allocate_classic_tt_bandwidth: Periodic endpoint "
		    "with zero endpoint maximum packet size is not supported");

		return (USB_NOT_SUPPORTED);
	}

	USB_DPRINTF_L3(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_allocate_classic_tt_bandwidth: bandwidth %d", bandwidth);

	mutex_enter(&parent_ud->usb_mutex);

	/*
	 * If the length in bytes plus the allocated bandwidth exceeds
	 * the maximum, return bandwidth allocation failure.
	 */
	if ((parent_ud->usb_hs_hub_min_bandwidth + bandwidth) >
	    FS_PERIODIC_BANDWIDTH) {

		mutex_exit(&parent_ud->usb_mutex);

		USB_DPRINTF_L2(PRINT_MASK_BW, ehcip->ehci_log_hdl,
		    "ehci_allocate_classic_tt_bandwidth: Reached maximum "
		    "bandwidth value and cannot allocate bandwidth for a "
		    "given low/full speed periodic endpoint");

		return (USB_NO_BANDWIDTH);
	}

	mutex_exit(&parent_ud->usb_mutex);

	/* Adjust polling interval to be a power of 2 */
	interval = ehci_adjust_polling_interval(ehcip, endpoint, port_status);

	/* Find the height in the tree */
	height = ehci_lattice_height(interval);

	/* Find the leftmost leaf in the subtree specified by the node. */
	leftmost = ehci_leftmost_leaf(pnode, height);

	mutex_enter(&parent_ud->usb_mutex);

	for (i = 0; i < (EHCI_NUM_INTR_QH_LISTS/interval); i++) {
		list = ehci_index[leftmost + i];

		if ((parent_ud->usb_hs_hub_bandwidth[list] +
		    bandwidth) > FS_PERIODIC_BANDWIDTH) {

			mutex_exit(&parent_ud->usb_mutex);

			USB_DPRINTF_L2(PRINT_MASK_BW, ehcip->ehci_log_hdl,
			    "ehci_allocate_classic_tt_bandwidth: Reached "
			    "maximum bandwidth value and cannot allocate "
			    "bandwidth for low/full periodic endpoint");

			return (USB_NO_BANDWIDTH);
		}
	}

	/*
	 * All the leaves for this node must be updated with the bandwidth.
	 */
	for (i = 0; i < (EHCI_NUM_INTR_QH_LISTS/interval); i++) {
		list = ehci_index[leftmost + i];
		parent_ud->usb_hs_hub_bandwidth[list] += bandwidth;
	}

	/* Find the leaf with the smallest allocated bandwidth */
	min = parent_ud->usb_hs_hub_bandwidth[0];

	for (i = 1; i < EHCI_NUM_INTR_QH_LISTS; i++) {
		if (parent_ud->usb_hs_hub_bandwidth[i] < min) {
			min = parent_ud->usb_hs_hub_bandwidth[i];
		}
	}

	/* Save the minimum for later use */
	parent_ud->usb_hs_hub_min_bandwidth = min;

	mutex_exit(&parent_ud->usb_mutex);

	return (USB_SUCCESS);
}


/*
 * ehci_deallocate_bandwidth:
 *
 * Deallocate bandwidth for the given node in the lattice and the length
 * of transfer.
 */
void
ehci_deallocate_bandwidth(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			pnode,
	uchar_t			smask,
	uchar_t			cmask)
{
	/* This routine is protected by the ehci_int_mutex */
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ehci_deallocate_high_speed_bandwidth(ehcip, ph, pnode, smask, cmask);

	/*
	 * For low/full speed usb devices, deallocate classic TT bandwidth
	 * in additional to high speed bandwidth.
	 */
	if (ph->p_usba_device->usb_port_status != USBA_HIGH_SPEED_DEV) {

		/* Deallocate classic TT bandwidth */
		ehci_deallocate_classic_tt_bandwidth(ehcip, ph, pnode);
	}
}


/*
 * ehci_deallocate_high_speed_bandwidth:
 *
 * Deallocate high speed bandwidth of a interrupt or isochronous endpoint.
 */
static void
ehci_deallocate_high_speed_bandwidth(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			pnode,
	uchar_t			smask,
	uchar_t			cmask)
{
	uint_t			height, leftmost;
	uint_t			list_count;
	uint_t			sbandwidth, cbandwidth;
	int			interval;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	usba_device_t		*child_ud;
	usb_port_status_t	port_status;

	/* This routine is protected by the ehci_int_mutex */
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get child's usba device structure */
	child_ud = ph->p_usba_device;

	mutex_enter(&child_ud->usb_mutex);

	/* Get the current usb device's port status */
	port_status = ph->p_usba_device->usb_port_status;

	mutex_exit(&child_ud->usb_mutex);

	(void) ehci_compute_high_speed_bandwidth(ehcip, endpoint,
	    port_status, &sbandwidth, &cbandwidth);

	/* Adjust polling interval to be a power of 2 */
	interval = ehci_adjust_polling_interval(ehcip, endpoint, port_status);

	/* Find the height in the tree */
	height = ehci_lattice_height(interval);

	/*
	 * Find the leftmost leaf in the subtree specified by the node
	 */
	leftmost = ehci_leftmost_leaf(pnode, height);

	list_count = EHCI_NUM_INTR_QH_LISTS/interval;

	/* Delete the bandwidth from the appropriate lists */
	if (port_status == USBA_HIGH_SPEED_DEV) {

		ehci_update_bw_availability(ehcip, -sbandwidth,
		    leftmost, list_count, smask);
	} else {
		if ((endpoint->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_INTR) {

			ehci_update_bw_availability(ehcip, -sbandwidth,
			    leftmost, list_count, smask);
			ehci_update_bw_availability(ehcip, -cbandwidth,
			    leftmost, list_count, cmask);
		} else {
			if ((endpoint->bEndpointAddress &
			    USB_EP_DIR_MASK) == USB_EP_DIR_IN) {

				ehci_update_bw_availability(ehcip, -sbandwidth,
				    leftmost, list_count, smask);
				ehci_update_bw_availability(ehcip,
				    -MAX_UFRAME_SITD_XFER, leftmost,
				    list_count, cmask);
			} else {

				ehci_update_bw_availability(ehcip,
				    -MAX_UFRAME_SITD_XFER, leftmost,
				    list_count, smask);
			}
		}
	}
}

/*
 * ehci_deallocate_classic_tt_bandwidth:
 *
 * Deallocate high speed bandwidth of a interrupt or isochronous endpoint.
 */
static void
ehci_deallocate_classic_tt_bandwidth(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			pnode)
{
	uint_t			bandwidth, height, leftmost, list, min;
	int			i, interval;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	usba_device_t		*child_ud, *parent_ud;
	usb_port_status_t	port_status;

	/* This routine is protected by the ehci_int_mutex */
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get child's usba device structure */
	child_ud = ph->p_usba_device;

	mutex_enter(&child_ud->usb_mutex);

	/* Get the current usb device's port status */
	port_status = child_ud->usb_port_status;

	/* Get the parent high speed hub's usba device structure */
	parent_ud = child_ud->usb_hs_hub_usba_dev;

	mutex_exit(&child_ud->usb_mutex);

	/* Obtain the bandwidth */
	(void) ehci_compute_classic_bandwidth(endpoint,
	    port_status, &bandwidth);

	/* Adjust polling interval to be a power of 2 */
	interval = ehci_adjust_polling_interval(ehcip, endpoint, port_status);

	/* Find the height in the tree */
	height = ehci_lattice_height(interval);

	/* Find the leftmost leaf in the subtree specified by the node */
	leftmost = ehci_leftmost_leaf(pnode, height);

	mutex_enter(&parent_ud->usb_mutex);

	/* Delete the bandwidth from the appropriate lists */
	for (i = 0; i < (EHCI_NUM_INTR_QH_LISTS/interval); i++) {
		list = ehci_index[leftmost + i];
		parent_ud->usb_hs_hub_bandwidth[list] -= bandwidth;
	}

	/* Find the leaf with the smallest allocated bandwidth */
	min = parent_ud->usb_hs_hub_bandwidth[0];

	for (i = 1; i < EHCI_NUM_INTR_QH_LISTS; i++) {
		if (parent_ud->usb_hs_hub_bandwidth[i] < min) {
			min = parent_ud->usb_hs_hub_bandwidth[i];
		}
	}

	/* Save the minimum for later use */
	parent_ud->usb_hs_hub_min_bandwidth = min;

	mutex_exit(&parent_ud->usb_mutex);
}


/*
 * ehci_compute_high_speed_bandwidth:
 *
 * Given a periodic endpoint (interrupt or isochronous) determine the total
 * bandwidth for one transaction. The EHCI host controller traverses the
 * endpoint descriptor lists on a first-come-first-serve basis. When the HC
 * services an endpoint, only a single transaction attempt is made. The  HC
 * moves to the next Endpoint Descriptor after the first transaction attempt
 * rather than finishing the entire Transfer Descriptor. Therefore, when  a
 * Transfer Descriptor is inserted into the lattice, we will only count the
 * number of bytes for one transaction.
 *
 * The following are the formulas used for  calculating bandwidth in  terms
 * bytes and it is for the single USB high speed transaction.  The protocol
 * overheads will be different for each of type of USB transfer & all these
 * formulas & protocol overheads are derived from the 5.11.3 section of the
 * USB 2.0 Specification.
 *
 * High-Speed:
 *		Protocol overhead + ((MaxPktSz * 7)/6) + Host_Delay
 *
 * Split Transaction: (Low/Full speed devices connected behind usb2.0 hub)
 *
 *		Protocol overhead + Split transaction overhead +
 *			((MaxPktSz * 7)/6) + Host_Delay;
 */
/* ARGSUSED */
static int
ehci_compute_high_speed_bandwidth(
	ehci_state_t		*ehcip,
	usb_ep_descr_t		*endpoint,
	usb_port_status_t	port_status,
	uint_t			*sbandwidth,
	uint_t			*cbandwidth)
{
	ushort_t		maxpacketsize = endpoint->wMaxPacketSize;

	/* Return failure if endpoint maximum packet is zero */
	if (maxpacketsize == 0) {
		USB_DPRINTF_L2(PRINT_MASK_BW, ehcip->ehci_log_hdl,
		    "ehci_allocate_high_speed_bandwidth: Periodic endpoint "
		    "with zero endpoint maximum packet size is not supported");

		return (USB_NOT_SUPPORTED);
	}

	/* Add bit-stuffing overhead */
	maxpacketsize = (ushort_t)((maxpacketsize * 7) / 6);

	/* Add Host Controller specific delay to required bandwidth */
	*sbandwidth = EHCI_HOST_CONTROLLER_DELAY;

	/* Add xfer specific protocol overheads */
	if ((endpoint->bmAttributes &
	    USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) {
		/* High speed interrupt transaction */
		*sbandwidth += HS_NON_ISOC_PROTO_OVERHEAD;
	} else {
		/* Isochronous transaction */
		*sbandwidth += HS_ISOC_PROTO_OVERHEAD;
	}

	/*
	 * For low/full speed devices, add split transaction specific
	 * overheads.
	 */
	if (port_status != USBA_HIGH_SPEED_DEV) {
		/*
		 * Add start and complete split transaction
		 * tokens overheads.
		 */
		*cbandwidth = *sbandwidth + COMPLETE_SPLIT_OVERHEAD;
		*sbandwidth += START_SPLIT_OVERHEAD;

		/* Add data overhead depending on data direction */
		if ((endpoint->bEndpointAddress &
		    USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
			*cbandwidth += maxpacketsize;
		} else {
			if ((endpoint->bmAttributes &
			    USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH) {
				/* There is no compete splits for out */
				*cbandwidth = 0;
			}
			*sbandwidth += maxpacketsize;
		}
	} else {
		uint_t		xactions;

		/* Get the max transactions per microframe */
		xactions = ((maxpacketsize & USB_EP_MAX_XACTS_MASK) >>
		    USB_EP_MAX_XACTS_SHIFT) + 1;

		/* High speed transaction */
		*sbandwidth += maxpacketsize;

		/* Calculate bandwidth per micro-frame */
		*sbandwidth *= xactions;

		*cbandwidth = 0;
	}

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_allocate_high_speed_bandwidth: "
	    "Start split bandwidth %d Complete split bandwidth %d",
	    *sbandwidth, *cbandwidth);

	return (USB_SUCCESS);
}


/*
 * ehci_compute_classic_bandwidth:
 *
 * Given a periodic endpoint (interrupt or isochronous) determine the total
 * bandwidth for one transaction. The EHCI host controller traverses the
 * endpoint descriptor lists on a first-come-first-serve basis. When the HC
 * services an endpoint, only a single transaction attempt is made. The  HC
 * moves to the next Endpoint Descriptor after the first transaction attempt
 * rather than finishing the entire Transfer Descriptor. Therefore, when  a
 * Transfer Descriptor is inserted into the lattice, we will only count the
 * number of bytes for one transaction.
 *
 * The following are the formulas used for  calculating bandwidth in  terms
 * bytes and it is for the single USB high speed transaction.  The protocol
 * overheads will be different for each of type of USB transfer & all these
 * formulas & protocol overheads are derived from the 5.11.3 section of the
 * USB 2.0 Specification.
 *
 * Low-Speed:
 *		Protocol overhead + Hub LS overhead +
 *		(Low Speed clock * ((MaxPktSz * 7)/6)) + TT_Delay
 *
 * Full-Speed:
 *		Protocol overhead + ((MaxPktSz * 7)/6) + TT_Delay
 */
/* ARGSUSED */
static int
ehci_compute_classic_bandwidth(
	usb_ep_descr_t		*endpoint,
	usb_port_status_t	port_status,
	uint_t			*bandwidth)
{
	ushort_t		maxpacketsize = endpoint->wMaxPacketSize;

	/*
	 * If endpoint maximum packet is zero, then return immediately.
	 */
	if (maxpacketsize == 0) {

		return (USB_NOT_SUPPORTED);
	}

	/* Add TT delay to required bandwidth */
	*bandwidth = TT_DELAY;

	/* Add bit-stuffing overhead */
	maxpacketsize = (ushort_t)((maxpacketsize * 7) / 6);

	switch (port_status) {
	case USBA_LOW_SPEED_DEV:
		/* Low speed interrupt transaction */
		*bandwidth += (LOW_SPEED_PROTO_OVERHEAD +
		    HUB_LOW_SPEED_PROTO_OVERHEAD +
		    (LOW_SPEED_CLOCK * maxpacketsize));
		break;
	case USBA_FULL_SPEED_DEV:
		/* Full speed transaction */
		*bandwidth += maxpacketsize;

		/* Add xfer specific protocol overheads */
		if ((endpoint->bmAttributes &
		    USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) {
			/* Full speed interrupt transaction */
			*bandwidth += FS_NON_ISOC_PROTO_OVERHEAD;
		} else {
			/* Isochronous and input transaction */
			if ((endpoint->bEndpointAddress &
			    USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
				*bandwidth += FS_ISOC_INPUT_PROTO_OVERHEAD;
			} else {
				/* Isochronous and output transaction */
				*bandwidth += FS_ISOC_OUTPUT_PROTO_OVERHEAD;
			}
		}
		break;
	}

	return (USB_SUCCESS);
}


/*
 * ehci_adjust_polling_interval:
 *
 * Adjust bandwidth according usb device speed.
 */
/* ARGSUSED */
int
ehci_adjust_polling_interval(
	ehci_state_t		*ehcip,
	usb_ep_descr_t		*endpoint,
	usb_port_status_t	port_status)
{
	uint_t			interval;
	int			i = 0;

	/* Get the polling interval */
	interval = endpoint->bInterval;

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_adjust_polling_interval: Polling interval 0x%x", interval);

	/*
	 * According USB 2.0 Specifications, a high-speed endpoint's
	 * polling intervals are specified interms of 125us or micro
	 * frame, where as full/low endpoint's polling intervals are
	 * specified in milliseconds.
	 *
	 * A high speed interrupt/isochronous endpoints can specify
	 * desired polling interval between 1 to 16 micro-frames,
	 * where as full/low endpoints can specify between 1 to 255
	 * milliseconds.
	 */
	switch (port_status) {
	case USBA_LOW_SPEED_DEV:
		/*
		 * Low speed  endpoints are limited to	specifying
		 * only 8ms to 255ms in this driver. If a device
		 * reports a polling interval that is less than 8ms,
		 * it will use 8 ms instead.
		 */
		if (interval < LS_MIN_POLL_INTERVAL) {

			USB_DPRINTF_L1(PRINT_MASK_BW, ehcip->ehci_log_hdl,
			    "Low speed endpoint's poll interval of %d ms "
			    "is below threshold. Rounding up to %d ms",
			    interval, LS_MIN_POLL_INTERVAL);

			interval = LS_MIN_POLL_INTERVAL;
		}

		/*
		 * Return an error if the polling interval is greater
		 * than 255ms.
		 */
		if (interval > LS_MAX_POLL_INTERVAL) {

			USB_DPRINTF_L1(PRINT_MASK_BW, ehcip->ehci_log_hdl,
			    "Low speed endpoint's poll interval is "
			    "greater than %d ms", LS_MAX_POLL_INTERVAL);

			return (USB_FAILURE);
		}
		break;

	case USBA_FULL_SPEED_DEV:
		/*
		 * Return an error if the polling interval is less
		 * than 1ms and greater than 255ms.
		 */
		if ((interval < FS_MIN_POLL_INTERVAL) &&
		    (interval > FS_MAX_POLL_INTERVAL)) {

			USB_DPRINTF_L1(PRINT_MASK_BW, ehcip->ehci_log_hdl,
			    "Full speed endpoint's poll interval must "
			    "be between %d and %d ms", FS_MIN_POLL_INTERVAL,
			    FS_MAX_POLL_INTERVAL);

			return (USB_FAILURE);
		}
		break;
	case USBA_HIGH_SPEED_DEV:
		/*
		 * Return an error if the polling interval is less 1
		 * and greater than 16. Convert this value to 125us
		 * units using 2^(bInterval -1). refer usb 2.0 spec
		 * page 51 for details.
		 */
		if ((interval < HS_MIN_POLL_INTERVAL) &&
		    (interval > HS_MAX_POLL_INTERVAL)) {

			USB_DPRINTF_L1(PRINT_MASK_BW, ehcip->ehci_log_hdl,
			    "High speed endpoint's poll interval "
			    "must be between %d and %d units",
			    HS_MIN_POLL_INTERVAL, HS_MAX_POLL_INTERVAL);

			return (USB_FAILURE);
		}

		/* Adjust high speed device polling interval */
		interval =
		    ehci_adjust_high_speed_polling_interval(ehcip, endpoint);

		break;
	}

	/*
	 * If polling interval is greater than 32ms,
	 * adjust polling interval equal to 32ms.
	 */
	if (interval > EHCI_NUM_INTR_QH_LISTS) {
		interval = EHCI_NUM_INTR_QH_LISTS;
	}

	/*
	 * Find the nearest power of 2 that's less
	 * than interval.
	 */
	while ((ehci_pow_2(i)) <= interval) {
		i++;
	}

	return (ehci_pow_2((i - 1)));
}


/*
 * ehci_adjust_high_speed_polling_interval:
 */
/* ARGSUSED */
static int
ehci_adjust_high_speed_polling_interval(
	ehci_state_t		*ehcip,
	usb_ep_descr_t		*endpoint)
{
	uint_t			interval;

	/* Get the polling interval */
	interval = ehci_pow_2(endpoint->bInterval - 1);

	/*
	 * Convert polling interval from micro seconds
	 * to milli seconds.
	 */
	if (interval <= EHCI_MAX_UFRAMES) {
		interval = 1;
	} else {
		interval = interval/EHCI_MAX_UFRAMES;
	}

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_adjust_high_speed_polling_interval: "
	    "High speed adjusted interval 0x%x", interval);

	return (interval);
}


/*
 * ehci_lattice_height:
 *
 * Given the requested bandwidth, find the height in the tree at which the
 * nodes for this bandwidth fall.  The height is measured as the number of
 * nodes from the leaf to the level specified by bandwidth The root of the
 * tree is at height TREE_HEIGHT.
 */
static uint_t
ehci_lattice_height(uint_t interval)
{
	return (TREE_HEIGHT - (ehci_log_2(interval)));
}


/*
 * ehci_lattice_parent:
 *
 * Given a node in the lattice, find the index of the parent node
 */
static uint_t
ehci_lattice_parent(uint_t node)
{
	if ((node % 2) == 0) {

		return ((node/2) - 1);
	} else {

		return ((node + 1)/2 - 1);
	}
}


/*
 * ehci_find_periodic_node:
 *
 * Based on the "real" array leaf node and interval, get the periodic node.
 */
static uint_t
ehci_find_periodic_node(uint_t leaf, int interval)
{
	uint_t	lattice_leaf;
	uint_t	height = ehci_lattice_height(interval);
	uint_t	pnode;
	int	i;

	/* Get the leaf number in the lattice */
	lattice_leaf = leaf + EHCI_NUM_INTR_QH_LISTS - 1;

	/* Get the node in the lattice based on the height and leaf */
	pnode = lattice_leaf;
	for (i = 0; i < height; i++) {
		pnode = ehci_lattice_parent(pnode);
	}

	return (pnode);
}


/*
 * ehci_leftmost_leaf:
 *
 * Find the leftmost leaf in the subtree specified by the node. Height refers
 * to number of nodes from the bottom of the tree to the node,	including the
 * node.
 *
 * The formula for a zero based tree is:
 *     2^H * Node + 2^H - 1
 * The leaf of the tree is an array, convert the number for the array.
 *     Subtract the size of nodes not in the array
 *     2^H * Node + 2^H - 1 - (EHCI_NUM_INTR_QH_LISTS - 1) =
 *     2^H * Node + 2^H - EHCI_NUM_INTR_QH_LISTS =
 *     2^H * (Node + 1) - EHCI_NUM_INTR_QH_LISTS
 *	   0
 *	 1   2
 *	0 1 2 3
 */
static uint_t
ehci_leftmost_leaf(
	uint_t	node,
	uint_t	height)
{
	return ((ehci_pow_2(height) * (node + 1)) - EHCI_NUM_INTR_QH_LISTS);
}


/*
 * ehci_pow_2:
 *
 * Compute 2 to the power
 */
static uint_t
ehci_pow_2(uint_t x)
{
	if (x == 0) {

		return (1);
	} else {

		return (2 << (x - 1));
	}
}


/*
 * ehci_log_2:
 *
 * Compute log base 2 of x
 */
static uint_t
ehci_log_2(uint_t x)
{
	int i = 0;

	while (x != 1) {
		x = x >> 1;
		i++;
	}

	return (i);
}


/*
 * ehci_find_bestfit_hs_mask:
 *
 * Find the smask and cmask in the bandwidth allocation, and update the
 * bandwidth allocation.
 */
static int
ehci_find_bestfit_hs_mask(
	ehci_state_t	*ehcip,
	uchar_t		*smask,
	uint_t		*pnode,
	usb_ep_descr_t	*endpoint,
	uint_t		bandwidth,
	int		interval)
{
	int		i;
	uint_t		elements, index;
	int		array_leaf, best_array_leaf;
	uint_t		node_bandwidth, best_node_bandwidth;
	uint_t		leaf_count;
	uchar_t		bw_mask;
	uchar_t		best_smask;

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_find_bestfit_hs_mask: ");

	/* Get all the valid smasks */
	switch (ehci_pow_2(endpoint->bInterval - 1)) {
	case EHCI_INTR_1US_POLL:
		index = EHCI_1US_MASK_INDEX;
		elements = EHCI_INTR_1US_POLL;
		break;
	case EHCI_INTR_2US_POLL:
		index = EHCI_2US_MASK_INDEX;
		elements = EHCI_INTR_2US_POLL;
		break;
	case EHCI_INTR_4US_POLL:
		index = EHCI_4US_MASK_INDEX;
		elements = EHCI_INTR_4US_POLL;
		break;
	case EHCI_INTR_XUS_POLL:
	default:
		index = EHCI_XUS_MASK_INDEX;
		elements = EHCI_INTR_XUS_POLL;
		break;
	}

	leaf_count = EHCI_NUM_INTR_QH_LISTS/interval;

	/*
	 * Because of the way the leaves are setup, we will automatically
	 * hit the leftmost leaf of every possible node with this interval.
	 */
	best_smask = 0x00;
	best_node_bandwidth = 0;
	for (array_leaf = 0; array_leaf < interval; array_leaf++) {
		/* Find the bandwidth mask */
		node_bandwidth = ehci_calculate_bw_availability_mask(ehcip,
		    bandwidth, ehci_index[array_leaf], leaf_count, &bw_mask);

		/*
		 * If this node cannot support our requirements skip to the
		 * next leaf.
		 */
		if (bw_mask == 0x00) {
			continue;
		}

		/*
		 * Now make sure our bandwidth requirements can be
		 * satisfied with one of smasks in this node.
		 */
		*smask = 0x00;
		for (i = index; i < (index + elements); i++) {
			/* Check the start split mask value */
			if (ehci_start_split_mask[index] & bw_mask) {
				*smask = ehci_start_split_mask[index];
				break;
			}
		}

		/*
		 * If an appropriate smask is found save the information if:
		 * o best_smask has not been found yet.
		 * - or -
		 * o This is the node with the least amount of bandwidth
		 */
		if ((*smask != 0x00) &&
		    ((best_smask == 0x00) ||
		    (best_node_bandwidth > node_bandwidth))) {

			best_node_bandwidth = node_bandwidth;
			best_array_leaf = array_leaf;
			best_smask = *smask;
		}
	}

	/*
	 * If we find node that can handle the bandwidth populate the
	 * appropriate variables and return success.
	 */
	if (best_smask) {
		*smask = best_smask;
		*pnode = ehci_find_periodic_node(ehci_index[best_array_leaf],
		    interval);
		ehci_update_bw_availability(ehcip, bandwidth,
		    ehci_index[best_array_leaf], leaf_count, best_smask);

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}


/*
 * ehci_find_bestfit_ls_intr_mask:
 *
 * Find the smask and cmask in the bandwidth allocation.
 */
static int
ehci_find_bestfit_ls_intr_mask(
	ehci_state_t	*ehcip,
	uchar_t		*smask,
	uchar_t		*cmask,
	uint_t		*pnode,
	uint_t		sbandwidth,
	uint_t		cbandwidth,
	int		interval)
{
	int		i;
	uint_t		elements, index;
	int		array_leaf, best_array_leaf;
	uint_t		node_sbandwidth, node_cbandwidth;
	uint_t		best_node_bandwidth;
	uint_t		leaf_count;
	uchar_t		bw_smask, bw_cmask;
	uchar_t		best_smask, best_cmask;

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_find_bestfit_ls_intr_mask: ");

	/* For low and full speed devices */
	index = EHCI_XUS_MASK_INDEX;
	elements = EHCI_INTR_4MS_POLL;

	leaf_count = EHCI_NUM_INTR_QH_LISTS/interval;

	/*
	 * Because of the way the leaves are setup, we will automatically
	 * hit the leftmost leaf of every possible node with this interval.
	 */
	best_smask = 0x00;
	best_node_bandwidth = 0;
	for (array_leaf = 0; array_leaf < interval; array_leaf++) {
		/* Find the bandwidth mask */
		node_sbandwidth = ehci_calculate_bw_availability_mask(ehcip,
		    sbandwidth, ehci_index[array_leaf], leaf_count, &bw_smask);
		node_cbandwidth = ehci_calculate_bw_availability_mask(ehcip,
		    cbandwidth, ehci_index[array_leaf], leaf_count, &bw_cmask);

		/*
		 * If this node cannot support our requirements skip to the
		 * next leaf.
		 */
		if ((bw_smask == 0x00) || (bw_cmask == 0x00)) {
			continue;
		}

		/*
		 * Now make sure our bandwidth requirements can be
		 * satisfied with one of smasks in this node.
		 */
		*smask = 0x00;
		*cmask = 0x00;
		for (i = index; i < (index + elements); i++) {
			/* Check the start split mask value */
			if ((ehci_start_split_mask[index] & bw_smask) &&
			    (ehci_intr_complete_split_mask[index] & bw_cmask)) {
				*smask = ehci_start_split_mask[index];
				*cmask = ehci_intr_complete_split_mask[index];
				break;
			}
		}

		/*
		 * If an appropriate smask is found save the information if:
		 * o best_smask has not been found yet.
		 * - or -
		 * o This is the node with the least amount of bandwidth
		 */
		if ((*smask != 0x00) &&
		    ((best_smask == 0x00) ||
		    (best_node_bandwidth >
		    (node_sbandwidth + node_cbandwidth)))) {
			best_node_bandwidth = node_sbandwidth + node_cbandwidth;
			best_array_leaf = array_leaf;
			best_smask = *smask;
			best_cmask = *cmask;
		}
	}

	/*
	 * If we find node that can handle the bandwidth populate the
	 * appropriate variables and return success.
	 */
	if (best_smask) {
		*smask = best_smask;
		*cmask = best_cmask;
		*pnode = ehci_find_periodic_node(ehci_index[best_array_leaf],
		    interval);
		ehci_update_bw_availability(ehcip, sbandwidth,
		    ehci_index[best_array_leaf], leaf_count, best_smask);
		ehci_update_bw_availability(ehcip, cbandwidth,
		    ehci_index[best_array_leaf], leaf_count, best_cmask);

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}


/*
 * ehci_find_bestfit_sitd_in_mask:
 *
 * Find the smask and cmask in the bandwidth allocation.
 */
static int
ehci_find_bestfit_sitd_in_mask(
	ehci_state_t	*ehcip,
	uchar_t		*smask,
	uchar_t		*cmask,
	uint_t		*pnode,
	uint_t		sbandwidth,
	uint_t		cbandwidth,
	int		interval)
{
	int		i, uFrames, found;
	int		array_leaf, best_array_leaf;
	uint_t		node_sbandwidth, node_cbandwidth;
	uint_t		best_node_bandwidth;
	uint_t		leaf_count;
	uchar_t		bw_smask, bw_cmask;
	uchar_t		best_smask, best_cmask;

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_find_bestfit_sitd_in_mask: ");

	leaf_count = EHCI_NUM_INTR_QH_LISTS/interval;

	/*
	 * Because of the way the leaves are setup, we will automatically
	 * hit the leftmost leaf of every possible node with this interval.
	 * You may only send MAX_UFRAME_SITD_XFER raw bits per uFrame.
	 */
	/*
	 * Need to add an additional 2 uFrames, if the "L"ast
	 * complete split is before uFrame 6.  See section
	 * 11.8.4 in USB 2.0 Spec.  Currently we do not support
	 * the "Back Ptr" which means we support on IN of
	 * ~4*MAX_UFRAME_SITD_XFER bandwidth/
	 */
	uFrames = (cbandwidth / MAX_UFRAME_SITD_XFER) + 2;
	if (cbandwidth % MAX_UFRAME_SITD_XFER) {
		uFrames++;
	}
	if (uFrames > 6) {

		return (USB_FAILURE);
	}
	*smask = 0x1;
	*cmask = 0x00;
	for (i = 0; i < uFrames; i++) {
		*cmask = *cmask << 1;
		*cmask |= 0x1;
	}
	/* cmask must start 2 frames after the smask */
	*cmask = *cmask << 2;

	found = 0;
	best_smask = 0x00;
	best_node_bandwidth = 0;
	for (array_leaf = 0; array_leaf < interval; array_leaf++) {
		node_sbandwidth = ehci_calculate_bw_availability_mask(ehcip,
		    sbandwidth, ehci_index[array_leaf], leaf_count, &bw_smask);
		node_cbandwidth = ehci_calculate_bw_availability_mask(ehcip,
		    MAX_UFRAME_SITD_XFER, ehci_index[array_leaf], leaf_count,
		    &bw_cmask);

		/*
		 * If this node cannot support our requirements skip to the
		 * next leaf.
		 */
		if ((bw_smask == 0x00) || (bw_cmask == 0x00)) {
			continue;
		}

		for (i = 0; i < (EHCI_MAX_UFRAMES - uFrames - 2); i++) {
			if ((*smask & bw_smask) && (*cmask & bw_cmask)) {
				found = 1;
				break;
			}
			*smask = *smask << 1;
			*cmask = *cmask << 1;
		}

		/*
		 * If an appropriate smask is found save the information if:
		 * o best_smask has not been found yet.
		 * - or -
		 * o This is the node with the least amount of bandwidth
		 */
		if (found &&
		    ((best_smask == 0x00) ||
		    (best_node_bandwidth >
		    (node_sbandwidth + node_cbandwidth)))) {
			best_node_bandwidth = node_sbandwidth + node_cbandwidth;
			best_array_leaf = array_leaf;
			best_smask = *smask;
			best_cmask = *cmask;
		}
	}

	/*
	 * If we find node that can handle the bandwidth populate the
	 * appropriate variables and return success.
	 */
	if (best_smask) {
		*smask = best_smask;
		*cmask = best_cmask;
		*pnode = ehci_find_periodic_node(ehci_index[best_array_leaf],
		    interval);
		ehci_update_bw_availability(ehcip, sbandwidth,
		    ehci_index[best_array_leaf], leaf_count, best_smask);
		ehci_update_bw_availability(ehcip, MAX_UFRAME_SITD_XFER,
		    ehci_index[best_array_leaf], leaf_count, best_cmask);

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}


/*
 * ehci_find_bestfit_sitd_out_mask:
 *
 * Find the smask in the bandwidth allocation.
 */
static int
ehci_find_bestfit_sitd_out_mask(
	ehci_state_t	*ehcip,
	uchar_t		*smask,
	uint_t		*pnode,
	uint_t		sbandwidth,
	int		interval)
{
	int		i, uFrames, found;
	int		array_leaf, best_array_leaf;
	uint_t		node_sbandwidth;
	uint_t		best_node_bandwidth;
	uint_t		leaf_count;
	uchar_t		bw_smask;
	uchar_t		best_smask;

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_find_bestfit_sitd_out_mask: ");

	leaf_count = EHCI_NUM_INTR_QH_LISTS/interval;

	/*
	 * Because of the way the leaves are setup, we will automatically
	 * hit the leftmost leaf of every possible node with this interval.
	 * You may only send MAX_UFRAME_SITD_XFER raw bits per uFrame.
	 */
	*smask = 0x00;
	uFrames = sbandwidth / MAX_UFRAME_SITD_XFER;
	if (sbandwidth % MAX_UFRAME_SITD_XFER) {
		uFrames++;
	}
	for (i = 0; i < uFrames; i++) {
		*smask = *smask << 1;
		*smask |= 0x1;
	}

	found = 0;
	best_smask = 0x00;
	best_node_bandwidth = 0;
	for (array_leaf = 0; array_leaf < interval; array_leaf++) {
		node_sbandwidth = ehci_calculate_bw_availability_mask(ehcip,
		    MAX_UFRAME_SITD_XFER, ehci_index[array_leaf], leaf_count,
		    &bw_smask);

		/*
		 * If this node cannot support our requirements skip to the
		 * next leaf.
		 */
		if (bw_smask == 0x00) {
			continue;
		}

		/* You cannot have a start split on the 8th uFrame */
		for (i = 0; (*smask & 0x80) == 0; i++) {
			if (*smask & bw_smask) {
				found = 1;
				break;
			}
			*smask = *smask << 1;
		}

		/*
		 * If an appropriate smask is found save the information if:
		 * o best_smask has not been found yet.
		 * - or -
		 * o This is the node with the least amount of bandwidth
		 */
		if (found &&
		    ((best_smask == 0x00) ||
		    (best_node_bandwidth > node_sbandwidth))) {
			best_node_bandwidth = node_sbandwidth;
			best_array_leaf = array_leaf;
			best_smask = *smask;
		}
	}

	/*
	 * If we find node that can handle the bandwidth populate the
	 * appropriate variables and return success.
	 */
	if (best_smask) {
		*smask = best_smask;
		*pnode = ehci_find_periodic_node(ehci_index[best_array_leaf],
		    interval);
		ehci_update_bw_availability(ehcip, MAX_UFRAME_SITD_XFER,
		    ehci_index[best_array_leaf], leaf_count, best_smask);

		return (USB_SUCCESS);
	}

	return (USB_FAILURE);
}


/*
 * ehci_calculate_bw_availability_mask:
 *
 * Returns the "total bandwidth used" in this node.
 * Populates bw_mask with the uFrames that can support the bandwidth.
 *
 * If all the Frames cannot support this bandwidth, then bw_mask
 * will return 0x00 and the "total bandwidth used" will be invalid.
 */
static uint_t
ehci_calculate_bw_availability_mask(
	ehci_state_t	*ehcip,
	uint_t		bandwidth,
	int		leaf,
	int		leaf_count,
	uchar_t		*bw_mask)
{
	int			i, j;
	uchar_t			bw_uframe;
	int			uframe_total;
	ehci_frame_bandwidth_t	*fbp;
	uint_t			total_bandwidth = 0;

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_calculate_bw_availability_mask: leaf %d leaf count %d",
	    leaf, leaf_count);

	/* Start by saying all uFrames are available */
	*bw_mask = 0xFF;

	for (i = 0; (i < leaf_count) || (*bw_mask == 0x00); i++) {
		fbp = &ehcip->ehci_frame_bandwidth[leaf + i];

		total_bandwidth += fbp->ehci_allocated_frame_bandwidth;

		for (j = 0; j < EHCI_MAX_UFRAMES; j++) {
			/*
			 * If the uFrame in bw_mask is available check to see if
			 * it can support the additional bandwidth.
			 */
			bw_uframe = (*bw_mask & (0x1 << j));
			uframe_total =
			    fbp->ehci_micro_frame_bandwidth[j] +
			    bandwidth;
			if ((bw_uframe) &&
			    (uframe_total > HS_PERIODIC_BANDWIDTH)) {
				*bw_mask = *bw_mask & ~bw_uframe;
			}
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_BW, ehcip->ehci_log_hdl,
	    "ehci_calculate_bw_availability_mask: bandwidth mask 0x%x",
	    *bw_mask);

	return (total_bandwidth);
}


/*
 * ehci_update_bw_availability:
 *
 * The leftmost leaf needs to be in terms of array position and
 * not the actual lattice position.
 */
static void
ehci_update_bw_availability(
	ehci_state_t	*ehcip,
	int		bandwidth,
	int		leftmost_leaf,
	int		leaf_count,
	uchar_t		mask)
{
	int			i, j;
	ehci_frame_bandwidth_t	*fbp;
	int			uFrame_bandwidth[8];

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_update_bw_availability: "
	    "leaf %d count %d bandwidth 0x%x mask 0x%x",
	    leftmost_leaf, leaf_count, bandwidth, mask);

	ASSERT(leftmost_leaf < 32);
	ASSERT(leftmost_leaf >= 0);

	for (j = 0; j < EHCI_MAX_UFRAMES; j++) {
		if (mask & 0x1) {
			uFrame_bandwidth[j] = bandwidth;
		} else {
			uFrame_bandwidth[j] = 0;
		}

		mask = mask >> 1;
	}

	/* Updated all the effected leafs with the bandwidth */
	for (i = 0; i < leaf_count; i++) {
		fbp = &ehcip->ehci_frame_bandwidth[leftmost_leaf + i];

		for (j = 0; j < EHCI_MAX_UFRAMES; j++) {
			fbp->ehci_micro_frame_bandwidth[j] +=
			    uFrame_bandwidth[j];
			fbp->ehci_allocated_frame_bandwidth +=
			    uFrame_bandwidth[j];
		}
	}
}

/*
 * Miscellaneous functions
 */

/*
 * ehci_obtain_state:
 *
 * NOTE: This function is also called from POLLED MODE.
 */
ehci_state_t *
ehci_obtain_state(dev_info_t	*dip)
{
	int			instance = ddi_get_instance(dip);

	ehci_state_t *state = ddi_get_soft_state(ehci_statep, instance);

	ASSERT(state != NULL);

	return (state);
}


/*
 * ehci_state_is_operational:
 *
 * Check the Host controller state and return proper values.
 */
int
ehci_state_is_operational(ehci_state_t	*ehcip)
{
	int	val;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	switch (ehcip->ehci_hc_soft_state) {
	case EHCI_CTLR_INIT_STATE:
	case EHCI_CTLR_SUSPEND_STATE:
		val = USB_FAILURE;
		break;
	case EHCI_CTLR_OPERATIONAL_STATE:
		val = USB_SUCCESS;
		break;
	case EHCI_CTLR_ERROR_STATE:
		val = USB_HC_HARDWARE_ERROR;
		break;
	default:
		val = USB_FAILURE;
		break;
	}

	return (val);
}


/*
 * ehci_do_soft_reset
 *
 * Do soft reset of ehci host controller.
 */
int
ehci_do_soft_reset(ehci_state_t	*ehcip)
{
	usb_frame_number_t	before_frame_number, after_frame_number;
	ehci_regs_t		*ehci_save_regs;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Increment host controller error count */
	ehcip->ehci_hc_error++;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_do_soft_reset:"
	    "Reset ehci host controller 0x%x", ehcip->ehci_hc_error);

	/*
	 * Allocate space for saving current Host Controller
	 * registers. Don't do any recovery if allocation
	 * fails.
	 */
	ehci_save_regs = (ehci_regs_t *)
	    kmem_zalloc(sizeof (ehci_regs_t), KM_NOSLEEP);

	if (ehci_save_regs == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_INTR,  ehcip->ehci_log_hdl,
		    "ehci_do_soft_reset: kmem_zalloc failed");

		return (USB_FAILURE);
	}

	/* Save current ehci registers */
	ehci_save_regs->ehci_command = Get_OpReg(ehci_command);
	ehci_save_regs->ehci_interrupt = Get_OpReg(ehci_interrupt);
	ehci_save_regs->ehci_ctrl_segment = Get_OpReg(ehci_ctrl_segment);
	ehci_save_regs->ehci_async_list_addr = Get_OpReg(ehci_async_list_addr);
	ehci_save_regs->ehci_config_flag = Get_OpReg(ehci_config_flag);
	ehci_save_regs->ehci_periodic_list_base =
	    Get_OpReg(ehci_periodic_list_base);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_do_soft_reset: Save reg = 0x%p", (void *)ehci_save_regs);

	/* Disable all list processing and interrupts */
	Set_OpReg(ehci_command, Get_OpReg(ehci_command) &
	    ~(EHCI_CMD_ASYNC_SCHED_ENABLE | EHCI_CMD_PERIODIC_SCHED_ENABLE));

	/* Disable all EHCI interrupts */
	Set_OpReg(ehci_interrupt, 0);

	/* Wait for few milliseconds */
	drv_usecwait(EHCI_SOF_TIMEWAIT);

	/* Do light soft reset of ehci host controller */
	Set_OpReg(ehci_command,
	    Get_OpReg(ehci_command) | EHCI_CMD_LIGHT_HC_RESET);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_do_soft_reset: Reset in progress");

	/* Wait for reset to complete */
	drv_usecwait(EHCI_RESET_TIMEWAIT);

	/*
	 * Restore previous saved EHCI register value
	 * into the current EHCI registers.
	 */
	Set_OpReg(ehci_ctrl_segment, (uint32_t)
	    ehci_save_regs->ehci_ctrl_segment);

	Set_OpReg(ehci_periodic_list_base, (uint32_t)
	    ehci_save_regs->ehci_periodic_list_base);

	Set_OpReg(ehci_async_list_addr, (uint32_t)
	    ehci_save_regs->ehci_async_list_addr);

	/*
	 * For some reason this register might get nulled out by
	 * the Uli M1575 South Bridge. To workaround the hardware
	 * problem, check the value after write and retry if the
	 * last write fails.
	 */
	if ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
	    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575) &&
	    (ehci_save_regs->ehci_async_list_addr !=
	    Get_OpReg(ehci_async_list_addr))) {
		int retry = 0;

		Set_OpRegRetry(ehci_async_list_addr, (uint32_t)
		    ehci_save_regs->ehci_async_list_addr, retry);
		if (retry >= EHCI_MAX_RETRY) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    ehcip->ehci_log_hdl, "ehci_do_soft_reset:"
			    " ASYNCLISTADDR write failed.");

			return (USB_FAILURE);
		}
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_do_soft_reset: ASYNCLISTADDR "
		    "write failed, retry=%d", retry);
	}

	Set_OpReg(ehci_config_flag, (uint32_t)
	    ehci_save_regs->ehci_config_flag);

	/* Enable both Asynchronous and Periodic Schedule if necessary */
	ehci_toggle_scheduler(ehcip);

	/*
	 * Set ehci_interrupt to enable all interrupts except Root
	 * Hub Status change and frame list rollover interrupts.
	 */
	Set_OpReg(ehci_interrupt, EHCI_INTR_HOST_SYSTEM_ERROR |
	    EHCI_INTR_FRAME_LIST_ROLLOVER |
	    EHCI_INTR_USB_ERROR |
	    EHCI_INTR_USB);

	/*
	 * Deallocate the space that allocated for saving
	 * HC registers.
	 */
	kmem_free((void *) ehci_save_regs, sizeof (ehci_regs_t));

	/*
	 * Set the desired interrupt threshold, frame list size (if
	 * applicable) and turn EHCI host controller.
	 */
	Set_OpReg(ehci_command, ((Get_OpReg(ehci_command) &
	    ~EHCI_CMD_INTR_THRESHOLD) |
	    (EHCI_CMD_01_INTR | EHCI_CMD_HOST_CTRL_RUN)));

	/* Wait 10ms for EHCI to start sending SOF */
	drv_usecwait(EHCI_RESET_TIMEWAIT);

	/*
	 * Get the current usb frame number before waiting for
	 * few milliseconds.
	 */
	before_frame_number = ehci_get_current_frame_number(ehcip);

	/* Wait for few milliseconds */
	drv_usecwait(EHCI_SOF_TIMEWAIT);

	/*
	 * Get the current usb frame number after waiting for
	 * few milliseconds.
	 */
	after_frame_number = ehci_get_current_frame_number(ehcip);

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_do_soft_reset: Before Frame Number 0x%llx "
	    "After Frame Number 0x%llx",
	    (unsigned long long)before_frame_number,
	    (unsigned long long)after_frame_number);

	if ((after_frame_number <= before_frame_number) &&
	    (Get_OpReg(ehci_status) & EHCI_STS_HOST_CTRL_HALTED)) {

		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_do_soft_reset: Soft reset failed");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * ehci_get_xfer_attrs:
 *
 * Get the attributes of a particular xfer.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
usb_req_attrs_t
ehci_get_xfer_attrs(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;
	usb_req_attrs_t		attrs = USB_ATTRS_NONE;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_get_xfer_attrs:");

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		attrs = ((usb_ctrl_req_t *)
		    tw->tw_curr_xfer_reqp)->ctrl_attributes;
		break;
	case USB_EP_ATTR_BULK:
		attrs = ((usb_bulk_req_t *)
		    tw->tw_curr_xfer_reqp)->bulk_attributes;
		break;
	case USB_EP_ATTR_INTR:
		attrs = ((usb_intr_req_t *)
		    tw->tw_curr_xfer_reqp)->intr_attributes;
		break;
	}

	return (attrs);
}


/*
 * ehci_get_current_frame_number:
 *
 * Get the current software based usb frame number.
 */
usb_frame_number_t
ehci_get_current_frame_number(ehci_state_t *ehcip)
{
	usb_frame_number_t	usb_frame_number;
	usb_frame_number_t	ehci_fno, micro_frame_number;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ehci_fno = ehcip->ehci_fno;
	micro_frame_number = Get_OpReg(ehci_frame_index) & 0x3FFF;

	/*
	 * Calculate current software based usb frame number.
	 *
	 * This code accounts for the fact that frame number is
	 * updated by the Host Controller before the ehci driver
	 * gets an FrameListRollover interrupt that will adjust
	 * Frame higher part.
	 *
	 * Refer ehci specification 1.0, section 2.3.2, page 21.
	 */
	micro_frame_number = ((micro_frame_number & 0x1FFF) |
	    ehci_fno) + (((micro_frame_number & 0x3FFF) ^
	    ehci_fno) & 0x2000);

	/*
	 * Micro Frame number is equivalent to 125 usec. Eight
	 * Micro Frame numbers are equivalent to one millsecond
	 * or one usb frame number.
	 */
	usb_frame_number = micro_frame_number >>
	    EHCI_uFRAMES_PER_USB_FRAME_SHIFT;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_get_current_frame_number: "
	    "Current usb uframe number = 0x%llx "
	    "Current usb frame number  = 0x%llx",
	    (unsigned long long)micro_frame_number,
	    (unsigned long long)usb_frame_number);

	return (usb_frame_number);
}


/*
 * ehci_cpr_cleanup:
 *
 * Cleanup ehci state and other ehci specific informations across
 * Check Point Resume (CPR).
 */
static	void
ehci_cpr_cleanup(ehci_state_t *ehcip)
{
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Reset software part of usb frame number */
	ehcip->ehci_fno = 0;
}


/*
 * ehci_wait_for_sof:
 *
 * Wait for couple of SOF interrupts
 */
int
ehci_wait_for_sof(ehci_state_t	*ehcip)
{
	usb_frame_number_t	before_frame_number, after_frame_number;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl, "ehci_wait_for_sof");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	error = ehci_state_is_operational(ehcip);

	if (error != USB_SUCCESS) {

		return (error);
	}

	/* Get the current usb frame number before waiting for two SOFs */
	before_frame_number = ehci_get_current_frame_number(ehcip);

	mutex_exit(&ehcip->ehci_int_mutex);

	/* Wait for few milliseconds */
	delay(drv_usectohz(EHCI_SOF_TIMEWAIT));

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Get the current usb frame number after woken up */
	after_frame_number = ehci_get_current_frame_number(ehcip);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_wait_for_sof: framenumber: before 0x%llx "
	    "after 0x%llx",
	    (unsigned long long)before_frame_number,
	    (unsigned long long)after_frame_number);

	/* Return failure, if usb frame number has not been changed */
	if (after_frame_number <= before_frame_number) {

		if ((ehci_do_soft_reset(ehcip)) != USB_SUCCESS) {

			USB_DPRINTF_L0(PRINT_MASK_LISTS,
			    ehcip->ehci_log_hdl, "No SOF interrupts");

			/* Set host controller soft state to error */
			ehcip->ehci_hc_soft_state = EHCI_CTLR_ERROR_STATE;

			return (USB_FAILURE);
		}

	}

	return (USB_SUCCESS);
}

/*
 * Toggle the async/periodic schedule based on opened pipe count.
 * During pipe cleanup(in pipe reset case), the pipe's QH is temporarily
 * disabled. But the TW on the pipe is not freed. In this case, we need
 * to disable async/periodic schedule for some non-compatible hardware.
 * Otherwise, the hardware will overwrite software's configuration of
 * the QH.
 */
void
ehci_toggle_scheduler_on_pipe(ehci_state_t *ehcip)
{
	uint_t  temp_reg, cmd_reg;

	cmd_reg = Get_OpReg(ehci_command);
	temp_reg = cmd_reg;

	/*
	 * Enable/Disable asynchronous scheduler, and
	 * turn on/off async list door bell
	 */
	if (ehcip->ehci_open_async_count) {
		if ((ehcip->ehci_async_req_count > 0) &&
		    ((cmd_reg & EHCI_CMD_ASYNC_SCHED_ENABLE) == 0)) {
			/*
			 * For some reason this address might get nulled out by
			 * the ehci chip. Set it here just in case it is null.
			 */
			Set_OpReg(ehci_async_list_addr,
			    ehci_qh_cpu_to_iommu(ehcip,
			    ehcip->ehci_head_of_async_sched_list));

			/*
			 * For some reason this register might get nulled out by
			 * the Uli M1575 Southbridge. To workaround the HW
			 * problem, check the value after write and retry if the
			 * last write fails.
			 *
			 * If the ASYNCLISTADDR remains "stuck" after
			 * EHCI_MAX_RETRY retries, then the M1575 is broken
			 * and is stuck in an inconsistent state and is about
			 * to crash the machine with a trn_oor panic when it
			 * does a DMA read from 0x0.  It is better to panic
			 * now rather than wait for the trn_oor crash; this
			 * way Customer Service will have a clean signature
			 * that indicts the M1575 chip rather than a
			 * mysterious and hard-to-diagnose trn_oor panic.
			 */
			if ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
			    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575) &&
			    (ehci_qh_cpu_to_iommu(ehcip,
			    ehcip->ehci_head_of_async_sched_list) !=
			    Get_OpReg(ehci_async_list_addr))) {
				int retry = 0;

				Set_OpRegRetry(ehci_async_list_addr,
				    ehci_qh_cpu_to_iommu(ehcip,
				    ehcip->ehci_head_of_async_sched_list),
				    retry);
				if (retry >= EHCI_MAX_RETRY)
					cmn_err(CE_PANIC,
					    "ehci_toggle_scheduler_on_pipe: "
					    "ASYNCLISTADDR write failed.");

				USB_DPRINTF_L2(PRINT_MASK_ATTA,
				    ehcip->ehci_log_hdl,
				    "ehci_toggle_scheduler_on_pipe:"
				    " ASYNCLISTADDR write failed, retry=%d",
				    retry);
			}

			cmd_reg |= EHCI_CMD_ASYNC_SCHED_ENABLE;
		}
	} else {
		cmd_reg &= ~EHCI_CMD_ASYNC_SCHED_ENABLE;
	}

	if (ehcip->ehci_open_periodic_count) {
		if ((ehcip->ehci_periodic_req_count > 0) &&
		    ((cmd_reg & EHCI_CMD_PERIODIC_SCHED_ENABLE) == 0)) {
			/*
			 * For some reason this address get's nulled out by
			 * the ehci chip. Set it here just in case it is null.
			 */
			Set_OpReg(ehci_periodic_list_base,
			    (uint32_t)(ehcip->ehci_pflt_cookie.dmac_address &
			    0xFFFFF000));
			cmd_reg |= EHCI_CMD_PERIODIC_SCHED_ENABLE;
		}
	} else {
		cmd_reg &= ~EHCI_CMD_PERIODIC_SCHED_ENABLE;
	}

	/* Just an optimization */
	if (temp_reg != cmd_reg) {
		Set_OpReg(ehci_command, cmd_reg);
	}
}


/*
 * ehci_toggle_scheduler:
 *
 * Turn scheduler based on pipe open count.
 */
void
ehci_toggle_scheduler(ehci_state_t *ehcip)
{
	uint_t	temp_reg, cmd_reg;

	/*
	 * For performance optimization, we need to change the bits
	 * if (async == 1||async == 0) OR (periodic == 1||periodic == 0)
	 *
	 * Related bits already enabled if
	 *	async and periodic req counts are > 1
	 *	OR async req count > 1 & no periodic pipe
	 *	OR periodic req count > 1 & no async pipe
	 */
	if (((ehcip->ehci_async_req_count > 1) &&
	    (ehcip->ehci_periodic_req_count > 1)) ||
	    ((ehcip->ehci_async_req_count > 1) &&
	    (ehcip->ehci_open_periodic_count == 0)) ||
	    ((ehcip->ehci_periodic_req_count > 1) &&
	    (ehcip->ehci_open_async_count == 0))) {
		USB_DPRINTF_L4(PRINT_MASK_ATTA,
		    ehcip->ehci_log_hdl, "ehci_toggle_scheduler:"
		    "async/periodic bits no need to change");

		return;
	}

	cmd_reg = Get_OpReg(ehci_command);
	temp_reg = cmd_reg;

	/*
	 * Enable/Disable asynchronous scheduler, and
	 * turn on/off async list door bell
	 */
	if (ehcip->ehci_async_req_count > 1) {
		/* we already enable the async bit */
		USB_DPRINTF_L4(PRINT_MASK_ATTA,
		    ehcip->ehci_log_hdl, "ehci_toggle_scheduler:"
		    "async bit already enabled: cmd_reg=0x%x", cmd_reg);
	} else if (ehcip->ehci_async_req_count == 1) {
		if (!(cmd_reg & EHCI_CMD_ASYNC_SCHED_ENABLE)) {
			/*
			 * For some reason this address might get nulled out by
			 * the ehci chip. Set it here just in case it is null.
			 * If it's not null, we should not reset the
			 * ASYNCLISTADDR, because it's updated by hardware to
			 * point to the next queue head to be executed.
			 */
			if (!Get_OpReg(ehci_async_list_addr)) {
				Set_OpReg(ehci_async_list_addr,
				    ehci_qh_cpu_to_iommu(ehcip,
				    ehcip->ehci_head_of_async_sched_list));
			}

			/*
			 * For some reason this register might get nulled out by
			 * the Uli M1575 Southbridge. To workaround the HW
			 * problem, check the value after write and retry if the
			 * last write fails.
			 *
			 * If the ASYNCLISTADDR remains "stuck" after
			 * EHCI_MAX_RETRY retries, then the M1575 is broken
			 * and is stuck in an inconsistent state and is about
			 * to crash the machine with a trn_oor panic when it
			 * does a DMA read from 0x0.  It is better to panic
			 * now rather than wait for the trn_oor crash; this
			 * way Customer Service will have a clean signature
			 * that indicts the M1575 chip rather than a
			 * mysterious and hard-to-diagnose trn_oor panic.
			 */
			if ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
			    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575) &&
			    (ehci_qh_cpu_to_iommu(ehcip,
			    ehcip->ehci_head_of_async_sched_list) !=
			    Get_OpReg(ehci_async_list_addr))) {
				int retry = 0;

				Set_OpRegRetry(ehci_async_list_addr,
				    ehci_qh_cpu_to_iommu(ehcip,
				    ehcip->ehci_head_of_async_sched_list),
				    retry);
				if (retry >= EHCI_MAX_RETRY)
					cmn_err(CE_PANIC,
					    "ehci_toggle_scheduler: "
					    "ASYNCLISTADDR write failed.");

				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    ehcip->ehci_log_hdl,
				    "ehci_toggle_scheduler: ASYNCLISTADDR "
				    "write failed, retry=%d", retry);
			}
		}
		cmd_reg |= EHCI_CMD_ASYNC_SCHED_ENABLE;
	} else {
		cmd_reg &= ~EHCI_CMD_ASYNC_SCHED_ENABLE;
	}

	if (ehcip->ehci_periodic_req_count > 1) {
		/* we already enable the periodic bit. */
		USB_DPRINTF_L4(PRINT_MASK_ATTA,
		    ehcip->ehci_log_hdl, "ehci_toggle_scheduler:"
		    "periodic bit already enabled: cmd_reg=0x%x", cmd_reg);
	} else if (ehcip->ehci_periodic_req_count == 1) {
		if (!(cmd_reg & EHCI_CMD_PERIODIC_SCHED_ENABLE)) {
			/*
			 * For some reason this address get's nulled out by
			 * the ehci chip. Set it here just in case it is null.
			 */
			Set_OpReg(ehci_periodic_list_base,
			    (uint32_t)(ehcip->ehci_pflt_cookie.dmac_address &
			    0xFFFFF000));
		}
		cmd_reg |= EHCI_CMD_PERIODIC_SCHED_ENABLE;
	} else {
		cmd_reg &= ~EHCI_CMD_PERIODIC_SCHED_ENABLE;
	}

	/* Just an optimization */
	if (temp_reg != cmd_reg) {
		Set_OpReg(ehci_command, cmd_reg);

		/* To make sure the command register is updated correctly */
		if ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
		    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575)) {
			int retry = 0;

			Set_OpRegRetry(ehci_command, cmd_reg, retry);
			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    ehcip->ehci_log_hdl,
			    "ehci_toggle_scheduler: CMD write failed, retry=%d",
			    retry);
		}

	}
}

/*
 * ehci print functions
 */

/*
 * ehci_print_caps:
 */
void
ehci_print_caps(ehci_state_t	*ehcip)
{
	uint_t			i;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "\n\tUSB 2.0 Host Controller Characteristics\n");

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Caps Length: 0x%x Version: 0x%x\n",
	    Get_8Cap(ehci_caps_length), Get_16Cap(ehci_version));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Structural Parameters\n");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Port indicators: %s", (Get_Cap(ehci_hcs_params) &
	    EHCI_HCS_PORT_INDICATOR) ? "Yes" : "No");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "No of Classic host controllers: 0x%x",
	    (Get_Cap(ehci_hcs_params) & EHCI_HCS_NUM_COMP_CTRLS)
	    >> EHCI_HCS_NUM_COMP_CTRL_SHIFT);
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "No of ports per Classic host controller: 0x%x",
	    (Get_Cap(ehci_hcs_params) & EHCI_HCS_NUM_PORTS_CC)
	    >> EHCI_HCS_NUM_PORTS_CC_SHIFT);
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Port routing rules: %s", (Get_Cap(ehci_hcs_params) &
	    EHCI_HCS_PORT_ROUTING_RULES) ? "Yes" : "No");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Port power control: %s", (Get_Cap(ehci_hcs_params) &
	    EHCI_HCS_PORT_POWER_CONTROL) ? "Yes" : "No");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "No of root hub ports: 0x%x\n",
	    Get_Cap(ehci_hcs_params) & EHCI_HCS_NUM_PORTS);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Capability Parameters\n");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "EHCI extended capability: %s", (Get_Cap(ehci_hcc_params) &
	    EHCI_HCC_EECP) ? "Yes" : "No");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Isoch schedule threshold: 0x%x",
	    Get_Cap(ehci_hcc_params) & EHCI_HCC_ISOCH_SCHED_THRESHOLD);
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Async schedule park capability: %s", (Get_Cap(ehci_hcc_params) &
	    EHCI_HCC_ASYNC_SCHED_PARK_CAP) ? "Yes" : "No");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Programmable frame list flag: %s", (Get_Cap(ehci_hcc_params) &
	    EHCI_HCC_PROG_FRAME_LIST_FLAG) ? "256/512/1024" : "1024");
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "64bit addressing capability: %s\n", (Get_Cap(ehci_hcc_params) &
	    EHCI_HCC_64BIT_ADDR_CAP) ? "Yes" : "No");

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Classic Port Route Description");

	for (i = 0; i < (Get_Cap(ehci_hcs_params) & EHCI_HCS_NUM_PORTS); i++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "\tPort Route 0x%x: 0x%x", i, Get_8Cap(ehci_port_route[i]));
	}
}


/*
 * ehci_print_regs:
 */
void
ehci_print_regs(ehci_state_t	*ehcip)
{
	uint_t			i;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "\n\tEHCI%d Operational Registers\n",
	    ddi_get_instance(ehcip->ehci_dip));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Command: 0x%x Status: 0x%x",
	    Get_OpReg(ehci_command), Get_OpReg(ehci_status));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Interrupt: 0x%x Frame Index: 0x%x",
	    Get_OpReg(ehci_interrupt), Get_OpReg(ehci_frame_index));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Control Segment: 0x%x Periodic List Base: 0x%x",
	    Get_OpReg(ehci_ctrl_segment), Get_OpReg(ehci_periodic_list_base));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Async List Addr: 0x%x Config Flag: 0x%x",
	    Get_OpReg(ehci_async_list_addr), Get_OpReg(ehci_config_flag));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "Root Hub Port Status");

	for (i = 0; i < (Get_Cap(ehci_hcs_params) & EHCI_HCS_NUM_PORTS); i++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "\tPort Status 0x%x: 0x%x ", i,
		    Get_OpReg(ehci_rh_port_status[i]));
	}
}


/*
 * ehci_print_qh:
 */
void
ehci_print_qh(
	ehci_state_t	*ehcip,
	ehci_qh_t	*qh)
{
	uint_t		i;

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_print_qh: qh = 0x%p", (void *)qh);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_link_ptr: 0x%x ", Get_QH(qh->qh_link_ptr));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_ctrl: 0x%x ", Get_QH(qh->qh_ctrl));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_split_ctrl: 0x%x ", Get_QH(qh->qh_split_ctrl));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_curr_qtd: 0x%x ", Get_QH(qh->qh_curr_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_next_qtd: 0x%x ", Get_QH(qh->qh_next_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_alt_next_qtd: 0x%x ", Get_QH(qh->qh_alt_next_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_status: 0x%x ", Get_QH(qh->qh_status));

	for (i = 0; i < 5; i++) {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "\tqh_buf[%d]: 0x%x ", i, Get_QH(qh->qh_buf[i]));
	}

	for (i = 0; i < 5; i++) {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "\tqh_buf_high[%d]: 0x%x ",
		    i, Get_QH(qh->qh_buf_high[i]));
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_dummy_qtd: 0x%x ", Get_QH(qh->qh_dummy_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_prev: 0x%x ", Get_QH(qh->qh_prev));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_state: 0x%x ", Get_QH(qh->qh_state));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_reclaim_next: 0x%x ", Get_QH(qh->qh_reclaim_next));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqh_reclaim_frame: 0x%x ", Get_QH(qh->qh_reclaim_frame));
}


/*
 * ehci_print_qtd:
 */
void
ehci_print_qtd(
	ehci_state_t	*ehcip,
	ehci_qtd_t	*qtd)
{
	uint_t		i;

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_print_qtd: qtd = 0x%p", (void *)qtd);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_next_qtd: 0x%x ", Get_QTD(qtd->qtd_next_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_alt_next_qtd: 0x%x ", Get_QTD(qtd->qtd_alt_next_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_ctrl: 0x%x ", Get_QTD(qtd->qtd_ctrl));

	for (i = 0; i < 5; i++) {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "\tqtd_buf[%d]: 0x%x ", i, Get_QTD(qtd->qtd_buf[i]));
	}

	for (i = 0; i < 5; i++) {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "\tqtd_buf_high[%d]: 0x%x ",
		    i, Get_QTD(qtd->qtd_buf_high[i]));
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_trans_wrapper: 0x%x ", Get_QTD(qtd->qtd_trans_wrapper));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_tw_next_qtd: 0x%x ", Get_QTD(qtd->qtd_tw_next_qtd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_active_qtd_next: 0x%x ", Get_QTD(qtd->qtd_active_qtd_next));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_active_qtd_prev: 0x%x ", Get_QTD(qtd->qtd_active_qtd_prev));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_state: 0x%x ", Get_QTD(qtd->qtd_state));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_ctrl_phase: 0x%x ", Get_QTD(qtd->qtd_ctrl_phase));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_xfer_offs: 0x%x ", Get_QTD(qtd->qtd_xfer_offs));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tqtd_xfer_len: 0x%x ", Get_QTD(qtd->qtd_xfer_len));
}

/*
 * ehci kstat functions
 */

/*
 * ehci_create_stats:
 *
 * Allocate and initialize the ehci kstat structures
 */
void
ehci_create_stats(ehci_state_t	*ehcip)
{
	char			kstatname[KSTAT_STRLEN];
	const char		*dname = ddi_driver_name(ehcip->ehci_dip);
	char			*usbtypes[USB_N_COUNT_KSTATS] =
	    {"ctrl", "isoch", "bulk", "intr"};
	uint_t			instance = ehcip->ehci_instance;
	ehci_intrs_stats_t	*isp;
	int			i;

	if (EHCI_INTRS_STATS(ehcip) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,intrs",
		    dname, instance);
		EHCI_INTRS_STATS(ehcip) = kstat_create("usba", instance,
		    kstatname, "usb_interrupts", KSTAT_TYPE_NAMED,
		    sizeof (ehci_intrs_stats_t) / sizeof (kstat_named_t),
		    KSTAT_FLAG_PERSISTENT);

		if (EHCI_INTRS_STATS(ehcip)) {
			isp = EHCI_INTRS_STATS_DATA(ehcip);
			kstat_named_init(&isp->ehci_sts_total,
			    "Interrupts Total", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_not_claimed,
			    "Not Claimed", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_async_sched_status,
			    "Async schedule status", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_periodic_sched_status,
			    "Periodic sched status", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_empty_async_schedule,
			    "Empty async schedule", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_host_ctrl_halted,
			    "Host controller Halted", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_async_advance_intr,
			    "Intr on async advance", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_host_system_error_intr,
			    "Host system error", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_frm_list_rollover_intr,
			    "Frame list rollover", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_rh_port_change_intr,
			    "Port change detect", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_usb_error_intr,
			    "USB error interrupt", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ehci_sts_usb_intr,
			    "USB interrupt", KSTAT_DATA_UINT64);

			EHCI_INTRS_STATS(ehcip)->ks_private = ehcip;
			EHCI_INTRS_STATS(ehcip)->ks_update = nulldev;
			kstat_install(EHCI_INTRS_STATS(ehcip));
		}
	}

	if (EHCI_TOTAL_STATS(ehcip) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,total",
		    dname, instance);
		EHCI_TOTAL_STATS(ehcip) = kstat_create("usba", instance,
		    kstatname, "usb_byte_count", KSTAT_TYPE_IO, 1,
		    KSTAT_FLAG_PERSISTENT);

		if (EHCI_TOTAL_STATS(ehcip)) {
			kstat_install(EHCI_TOTAL_STATS(ehcip));
		}
	}

	for (i = 0; i < USB_N_COUNT_KSTATS; i++) {
		if (ehcip->ehci_count_stats[i] == NULL) {
			(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,%s",
			    dname, instance, usbtypes[i]);
			ehcip->ehci_count_stats[i] = kstat_create("usba",
			    instance, kstatname, "usb_byte_count",
			    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);

			if (ehcip->ehci_count_stats[i]) {
				kstat_install(ehcip->ehci_count_stats[i]);
			}
		}
	}
}


/*
 * ehci_destroy_stats:
 *
 * Clean up ehci kstat structures
 */
void
ehci_destroy_stats(ehci_state_t	*ehcip)
{
	int	i;

	if (EHCI_INTRS_STATS(ehcip)) {
		kstat_delete(EHCI_INTRS_STATS(ehcip));
		EHCI_INTRS_STATS(ehcip) = NULL;
	}

	if (EHCI_TOTAL_STATS(ehcip)) {
		kstat_delete(EHCI_TOTAL_STATS(ehcip));
		EHCI_TOTAL_STATS(ehcip) = NULL;
	}

	for (i = 0; i < USB_N_COUNT_KSTATS; i++) {
		if (ehcip->ehci_count_stats[i]) {
			kstat_delete(ehcip->ehci_count_stats[i]);
			ehcip->ehci_count_stats[i] = NULL;
		}
	}
}


/*
 * ehci_do_intrs_stats:
 *
 * ehci status information
 */
void
ehci_do_intrs_stats(
	ehci_state_t	*ehcip,
	int		val)
{
	if (EHCI_INTRS_STATS(ehcip)) {
		EHCI_INTRS_STATS_DATA(ehcip)->ehci_sts_total.value.ui64++;
		switch (val) {
		case EHCI_STS_ASYNC_SCHED_STATUS:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_async_sched_status.value.ui64++;
			break;
		case EHCI_STS_PERIODIC_SCHED_STATUS:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_periodic_sched_status.value.ui64++;
			break;
		case EHCI_STS_EMPTY_ASYNC_SCHEDULE:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_empty_async_schedule.value.ui64++;
			break;
		case EHCI_STS_HOST_CTRL_HALTED:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_host_ctrl_halted.value.ui64++;
			break;
		case EHCI_STS_ASYNC_ADVANCE_INTR:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_async_advance_intr.value.ui64++;
			break;
		case EHCI_STS_HOST_SYSTEM_ERROR_INTR:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_host_system_error_intr.value.ui64++;
			break;
		case EHCI_STS_FRM_LIST_ROLLOVER_INTR:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_frm_list_rollover_intr.value.ui64++;
			break;
		case EHCI_STS_RH_PORT_CHANGE_INTR:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_rh_port_change_intr.value.ui64++;
			break;
		case EHCI_STS_USB_ERROR_INTR:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_usb_error_intr.value.ui64++;
			break;
		case EHCI_STS_USB_INTR:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_usb_intr.value.ui64++;
			break;
		default:
			EHCI_INTRS_STATS_DATA(ehcip)->
			    ehci_sts_not_claimed.value.ui64++;
			break;
		}
	}
}


/*
 * ehci_do_byte_stats:
 *
 * ehci data xfer information
 */
void
ehci_do_byte_stats(
	ehci_state_t	*ehcip,
	size_t		len,
	uint8_t		attr,
	uint8_t		addr)
{
	uint8_t 	type = attr & USB_EP_ATTR_MASK;
	uint8_t 	dir = addr & USB_EP_DIR_MASK;

	if (dir == USB_EP_DIR_IN) {
		EHCI_TOTAL_STATS_DATA(ehcip)->reads++;
		EHCI_TOTAL_STATS_DATA(ehcip)->nread += len;
		switch (type) {
			case USB_EP_ATTR_CONTROL:
				EHCI_CTRL_STATS(ehcip)->reads++;
				EHCI_CTRL_STATS(ehcip)->nread += len;
				break;
			case USB_EP_ATTR_BULK:
				EHCI_BULK_STATS(ehcip)->reads++;
				EHCI_BULK_STATS(ehcip)->nread += len;
				break;
			case USB_EP_ATTR_INTR:
				EHCI_INTR_STATS(ehcip)->reads++;
				EHCI_INTR_STATS(ehcip)->nread += len;
				break;
			case USB_EP_ATTR_ISOCH:
				EHCI_ISOC_STATS(ehcip)->reads++;
				EHCI_ISOC_STATS(ehcip)->nread += len;
				break;
		}
	} else if (dir == USB_EP_DIR_OUT) {
		EHCI_TOTAL_STATS_DATA(ehcip)->writes++;
		EHCI_TOTAL_STATS_DATA(ehcip)->nwritten += len;
		switch (type) {
			case USB_EP_ATTR_CONTROL:
				EHCI_CTRL_STATS(ehcip)->writes++;
				EHCI_CTRL_STATS(ehcip)->nwritten += len;
				break;
			case USB_EP_ATTR_BULK:
				EHCI_BULK_STATS(ehcip)->writes++;
				EHCI_BULK_STATS(ehcip)->nwritten += len;
				break;
			case USB_EP_ATTR_INTR:
				EHCI_INTR_STATS(ehcip)->writes++;
				EHCI_INTR_STATS(ehcip)->nwritten += len;
				break;
			case USB_EP_ATTR_ISOCH:
				EHCI_ISOC_STATS(ehcip)->writes++;
				EHCI_ISOC_STATS(ehcip)->nwritten += len;
				break;
		}
	}
}
