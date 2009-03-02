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


/*
 * Universal Host Controller Driver (UHCI)
 *
 * The UHCI driver is a driver which interfaces to the Universal
 * Serial Bus Driver (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the UHCI.
 * This file contains misc functions.
 */
#include <sys/usb/hcd/uhci/uhcid.h>
#include <sys/usb/hcd/uhci/uhciutil.h>
#include <sys/usb/hcd/uhci/uhcipolled.h>

#include <sys/disp.h>

/* Globals */
extern uint_t	uhci_td_pool_size;			/* Num TDs */
extern uint_t	uhci_qh_pool_size;			/* Num QHs */
extern ushort_t	uhci_tree_bottom_nodes[];
extern void	*uhci_statep;

/* function prototypes */
static void	uhci_build_interrupt_lattice(uhci_state_t *uhcip);
static int	uhci_init_frame_lst_table(dev_info_t *dip, uhci_state_t *uhcip);

static uint_t	uhci_lattice_height(uint_t bandwidth);
static uint_t	uhci_lattice_parent(uint_t node);
static uint_t	uhci_leftmost_leaf(uint_t node, uint_t height);
static uint_t	uhci_compute_total_bandwidth(usb_ep_descr_t *endpoint,
		    usb_port_status_t port_status);

static int	uhci_bandwidth_adjust(uhci_state_t *uhcip,
		    usb_ep_descr_t *endpoint, usb_port_status_t port_status);

static uhci_td_t *uhci_allocate_td_from_pool(uhci_state_t *uhcip);
static void	uhci_fill_in_td(uhci_state_t *uhcip,
		    uhci_td_t *td, uhci_td_t *current_dummy,
		    uint32_t buffer_offset, size_t length,
		    uhci_pipe_private_t	*pp, uchar_t PID,
		    usb_req_attrs_t attrs, uhci_trans_wrapper_t *tw);
static uint32_t	uhci_get_tw_paddr_by_offs(uhci_state_t *uhcip,
		    uint32_t buffer_offset, size_t length,
		    uhci_trans_wrapper_t *tw);
static uhci_trans_wrapper_t *uhci_create_transfer_wrapper(
		    uhci_state_t *uhcip, uhci_pipe_private_t *pp,
		    size_t length, usb_flags_t usb_flags);
static uhci_trans_wrapper_t *uhci_create_isoc_transfer_wrapper(
		    uhci_state_t *uhcip, uhci_pipe_private_t *pp,
		    usb_isoc_req_t *req, size_t length,
		    usb_flags_t usb_flags);

static int	uhci_create_setup_pkt(uhci_state_t *uhcip,
		    uhci_pipe_private_t	*pp, uhci_trans_wrapper_t *tw);
static void	uhci_insert_ctrl_qh(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp);
static void	uhci_remove_ctrl_qh(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp);
static void	uhci_insert_intr_qh(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp);
static void	uhci_remove_intr_qh(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp);
static void	uhci_remove_bulk_qh(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp);
static void	uhci_insert_bulk_qh(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp);
static void	uhci_handle_bulk_td_errors(uhci_state_t *uhcip, uhci_td_t *td);
static int	uhci_alloc_memory_for_tds(uhci_state_t *uhcip, uint_t num_tds,
		    uhci_bulk_isoc_xfer_t *info);
static int	uhci_alloc_bulk_isoc_tds(uhci_state_t *uhcip, uint_t num_tds,
		    uhci_bulk_isoc_xfer_t *info);
static void	uhci_get_isoc_td_by_index(uhci_state_t *uhcip,
		    uhci_bulk_isoc_xfer_t *info, uint_t index,
		    uhci_td_t **tdpp, uhci_bulk_isoc_td_pool_t **td_pool_pp);
static void	uhci_get_bulk_td_by_paddr(uhci_state_t *uhcip,
		    uhci_bulk_isoc_xfer_t *info, uint32_t paddr,
		    uhci_bulk_isoc_td_pool_t **td_pool_pp);

static	int	uhci_handle_isoc_receive(uhci_state_t *uhcip,
		uhci_pipe_private_t *pp, uhci_trans_wrapper_t *tw);
static void	uhci_delete_isoc_td(uhci_state_t *uhcip,
		    uhci_td_t *td);
#ifdef DEBUG
static void	uhci_print_td(uhci_state_t *uhcip, uhci_td_t *td);
static void	uhci_print_qh(uhci_state_t *uhcip, queue_head_t *qh);
#endif


/*
 * uhci_build_interrupt_lattice:
 *
 * Construct the interrupt lattice tree using static Queue Head pointers.
 * This interrupt lattice tree will have total of 63 queue heads and the
 * Host Controller (HC) processes queue heads every frame.
 */
static void
uhci_build_interrupt_lattice(uhci_state_t *uhcip)
{
	int			half_list = NUM_INTR_QH_LISTS / 2;
	uint16_t		i, j, k;
	uhci_td_t		*sof_td, *isoc_td;
	uintptr_t		addr;
	queue_head_t		*list_array = uhcip->uhci_qh_pool_addr;
	queue_head_t		*tmp_qh;
	frame_lst_table_t	*frame_lst_tablep =
	    uhcip->uhci_frame_lst_tablep;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_build_interrupt_lattice:");

	/*
	 * Reserve the first 63 queue head structures in the pool as static
	 * queue heads & these are required for constructing interrupt
	 * lattice tree.
	 */
	for (i = 0; i < NUM_INTR_QH_LISTS; i++) {
		SetQH32(uhcip, list_array[i].link_ptr, HC_END_OF_LIST);
		SetQH32(uhcip, list_array[i].element_ptr, HC_END_OF_LIST);
		list_array[i].qh_flag		= QUEUE_HEAD_FLAG_STATIC;
		list_array[i].node		= i;
	}

	/* Build the interrupt lattice tree */
	for (i = 0; i < half_list - 1; i++) {
		/*
		 * The next  pointer in the host controller  queue head
		 * descriptor must contain an iommu address. Calculate
		 * the offset into the cpu address and add this to the
		 * starting iommu address.
		 */
		addr = QH_PADDR(&list_array[i]) | HC_QUEUE_HEAD;

		SetQH32(uhcip, list_array[2*i + 1].link_ptr, addr);
		SetQH32(uhcip, list_array[2*i + 2].link_ptr, addr);
	}

	/*
	 * Initialize the interrupt list in the Frame list Table
	 * so that it points to the bottom of the tree.
	 */
	for (i = 0, j = 0; i < pow_2(TREE_HEIGHT); i++) {
		addr = QH_PADDR(&list_array[half_list + i - 1]);
		for (k = 0; k <  pow_2(VIRTUAL_TREE_HEIGHT); k++) {
			SetFL32(uhcip,
			    frame_lst_tablep[uhci_tree_bottom_nodes[j++]],
			    addr | HC_QUEUE_HEAD);
		}
	}

	/*
	 *  Create a controller and bulk Queue heads
	 */
	uhcip->uhci_ctrl_xfers_q_head = uhci_alloc_queue_head(uhcip);
	tmp_qh = uhcip->uhci_ctrl_xfers_q_tail = uhcip->uhci_ctrl_xfers_q_head;

	SetQH32(uhcip, list_array[0].link_ptr,
	    (QH_PADDR(tmp_qh) | HC_QUEUE_HEAD));

	uhcip->uhci_bulk_xfers_q_head = uhci_alloc_queue_head(uhcip);
	uhcip->uhci_bulk_xfers_q_tail = uhcip->uhci_bulk_xfers_q_head;
	SetQH32(uhcip, tmp_qh->link_ptr,
	    (QH_PADDR(uhcip->uhci_bulk_xfers_q_head)|HC_QUEUE_HEAD));

	SetQH32(uhcip, uhcip->uhci_bulk_xfers_q_head->link_ptr, HC_END_OF_LIST);

	/*
	 * Add a dummy TD to the static queue head 0. THis is used
	 * to generate an at the end of frame.
	 */
	sof_td = uhci_allocate_td_from_pool(uhcip);

	SetQH32(uhcip, list_array[0].element_ptr,
	    TD_PADDR(sof_td) | HC_TD_HEAD);
	SetTD32(uhcip, sof_td->link_ptr, HC_END_OF_LIST);
	uhcip->uhci_sof_td = sof_td;

	/*
	 * Add a dummy td that is used to generate an interrupt for
	 * every 1024 frames.
	 */
	isoc_td = uhci_allocate_td_from_pool(uhcip);
	SetTD32(uhcip, isoc_td->link_ptr, HC_END_OF_LIST);
	uhcip->uhci_isoc_td = isoc_td;

	uhcip->uhci_isoc_qh = uhci_alloc_queue_head(uhcip);
	SetQH32(uhcip, uhcip->uhci_isoc_qh->link_ptr,
	    GetFL32(uhcip, uhcip->uhci_frame_lst_tablep[MAX_FRAME_NUM]));
	SetQH32(uhcip, uhcip->uhci_isoc_qh->element_ptr, TD_PADDR(isoc_td));
	SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[MAX_FRAME_NUM],
	    QH_PADDR(uhcip->uhci_isoc_qh) | HC_QUEUE_HEAD);
}


/*
 * uhci_allocate_pools:
 *	Allocate the system memory for the Queue Heads Descriptor and
 *	for the Transfer Descriptor (TD) pools. Both QH and TD structures
 *	must be aligned to a 16 byte boundary.
 */
int
uhci_allocate_pools(uhci_state_t *uhcip)
{
	dev_info_t		*dip = uhcip->uhci_dip;
	size_t			real_length;
	int			i, result;
	uint_t			ccount;
	ddi_device_acc_attr_t	dev_attr;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_allocate_pools:");

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* Allocate the TD pool DMA handle */
	if (ddi_dma_alloc_handle(dip, &uhcip->uhci_dma_attr, DDI_DMA_SLEEP, 0,
	    &uhcip->uhci_td_pool_dma_handle) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	/* Allocate the memory for the TD pool */
	if (ddi_dma_mem_alloc(uhcip->uhci_td_pool_dma_handle,
	    uhci_td_pool_size * sizeof (uhci_td_t),
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    (caddr_t *)&uhcip->uhci_td_pool_addr, &real_length,
	    &uhcip->uhci_td_pool_mem_handle)) {

		return (USB_FAILURE);
	}

	/* Map the TD pool into the I/O address space */
	result = ddi_dma_addr_bind_handle(uhcip->uhci_td_pool_dma_handle,
	    NULL, (caddr_t)uhcip->uhci_td_pool_addr, real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &uhcip->uhci_td_pool_cookie, &ccount);

	bzero((void *)uhcip->uhci_td_pool_addr,
	    uhci_td_pool_size * sizeof (uhci_td_t));

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_allocate_pools: More than 1 cookie");

			return (USB_FAILURE);
		}
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_allocate_pools: Result = %d", result);

		uhci_decode_ddi_dma_addr_bind_handle_result(uhcip, result);

		return (USB_FAILURE);
	}

	uhcip->uhci_dma_addr_bind_flag |= UHCI_TD_POOL_BOUND;

	/* Initialize the TD pool */
	for (i = 0; i < uhci_td_pool_size; i++) {
		uhcip->uhci_td_pool_addr[i].flag = TD_FLAG_FREE;
	}

	/* Allocate the TD pool DMA handle */
	if (ddi_dma_alloc_handle(dip, &uhcip->uhci_dma_attr, DDI_DMA_SLEEP,
	    0, &uhcip->uhci_qh_pool_dma_handle) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	/* Allocate the memory for the QH pool */
	if (ddi_dma_mem_alloc(uhcip->uhci_qh_pool_dma_handle,
	    uhci_qh_pool_size * sizeof (queue_head_t),
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
	    (caddr_t *)&uhcip->uhci_qh_pool_addr, &real_length,
	    &uhcip->uhci_qh_pool_mem_handle) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	result = ddi_dma_addr_bind_handle(uhcip->uhci_qh_pool_dma_handle,
	    NULL, (caddr_t)uhcip->uhci_qh_pool_addr, real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &uhcip->uhci_qh_pool_cookie, &ccount);

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_allocate_pools: More than 1 cookie");

			return (USB_FAILURE);
		}
	} else {
		uhci_decode_ddi_dma_addr_bind_handle_result(uhcip, result);

		return (USB_FAILURE);
	}

	uhcip->uhci_dma_addr_bind_flag |= UHCI_QH_POOL_BOUND;

	bzero((void *)uhcip->uhci_qh_pool_addr,
	    uhci_qh_pool_size * sizeof (queue_head_t));

	/* Initialize the QH pool */
	for (i = 0; i < uhci_qh_pool_size; i ++) {
		uhcip->uhci_qh_pool_addr[i].qh_flag = QUEUE_HEAD_FLAG_FREE;
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_allocate_pools: Completed");

	return (USB_SUCCESS);
}


/*
 * uhci_free_pools:
 *	Cleanup on attach failure or detach
 */
void
uhci_free_pools(uhci_state_t *uhcip)
{
	int			i, flag, rval;
	uhci_td_t		*td;
	uhci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_free_pools:");

	if (uhcip->uhci_td_pool_addr && uhcip->uhci_td_pool_mem_handle) {
		for (i = 0; i < uhci_td_pool_size; i ++) {
			td = &uhcip->uhci_td_pool_addr[i];

			flag = uhcip->uhci_td_pool_addr[i].flag;
			if ((flag != TD_FLAG_FREE) &&
			    (flag != TD_FLAG_DUMMY) && (td->tw != NULL)) {
				tw = td->tw;
				uhci_free_tw(uhcip, tw);
			}

		}

		if (uhcip->uhci_dma_addr_bind_flag & UHCI_TD_POOL_BOUND) {
			rval = ddi_dma_unbind_handle(
			    uhcip->uhci_td_pool_dma_handle);
			ASSERT(rval == DDI_SUCCESS);
		}

		ddi_dma_mem_free(&uhcip->uhci_td_pool_mem_handle);
	}

	/* Free the TD pool */
	if (uhcip->uhci_td_pool_dma_handle) {
		ddi_dma_free_handle(&uhcip->uhci_td_pool_dma_handle);
	}

	if (uhcip->uhci_qh_pool_addr && uhcip->uhci_qh_pool_mem_handle) {
		if (uhcip->uhci_dma_addr_bind_flag & UHCI_QH_POOL_BOUND) {
			rval = ddi_dma_unbind_handle(
			    uhcip->uhci_qh_pool_dma_handle);
			ASSERT(rval == DDI_SUCCESS);
		}
		ddi_dma_mem_free(&uhcip->uhci_qh_pool_mem_handle);
	}

	/* Free the QH pool */
	if (uhcip->uhci_qh_pool_dma_handle) {
		ddi_dma_free_handle(&uhcip->uhci_qh_pool_dma_handle);
	}

	/* Free the Frame list Table area */
	if (uhcip->uhci_frame_lst_tablep && uhcip->uhci_flt_mem_handle) {
		if (uhcip->uhci_dma_addr_bind_flag & UHCI_FLA_POOL_BOUND) {
			rval = ddi_dma_unbind_handle(
			    uhcip->uhci_flt_dma_handle);
			ASSERT(rval == DDI_SUCCESS);
		}
		ddi_dma_mem_free(&uhcip->uhci_flt_mem_handle);
	}

	if (uhcip->uhci_flt_dma_handle) {
		ddi_dma_free_handle(&uhcip->uhci_flt_dma_handle);
	}
}


/*
 * uhci_decode_ddi_dma_addr_bind_handle_result:
 *	Process the return values of ddi_dma_addr_bind_handle()
 */
void
uhci_decode_ddi_dma_addr_bind_handle_result(uhci_state_t *uhcip, int result)
{
	char *msg;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_decode_ddi_dma_addr_bind_handle_result:");

	switch (result) {
	case DDI_DMA_PARTIAL_MAP:
		msg = "Partial transfers not allowed";
		break;
	case DDI_DMA_INUSE:
		msg = "Handle is in use";
		break;
	case DDI_DMA_NORESOURCES:
		msg = "No resources";
		break;
	case DDI_DMA_NOMAPPING:
		msg = "No mapping";
		break;
	case DDI_DMA_TOOBIG:
		msg = "Object is too big";
		break;
	default:
		msg = "Unknown dma error";
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uhcip->uhci_log_hdl, "%s", msg);
}


/*
 * uhci_init_ctlr:
 *	Initialize the Host Controller (HC).
 */
int
uhci_init_ctlr(uhci_state_t *uhcip)
{
	dev_info_t *dip = uhcip->uhci_dip;
	uint_t	cmd_reg;
	uint_t	frame_base_addr;

	mutex_enter(&uhcip->uhci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl, "uhci_init_ctlr:");

	/*
	 * When USB legacy mode is enabled, the BIOS manages the USB keyboard
	 * attached to the UHCI controller. It has been observed that some
	 * times the BIOS does not clear the interrupts in the legacy mode
	 * register in the PCI configuration space. So, disable the SMI intrs
	 * and route the intrs to PIRQD here.
	 */
	pci_config_put16(uhcip->uhci_config_handle,
	    LEGACYMODE_REG_OFFSET, LEGACYMODE_REG_INIT_VALUE);

	/*
	 * Disable all the interrupts.
	 */
	Set_OpReg16(USBINTR, DISABLE_ALL_INTRS);

	cmd_reg = Get_OpReg16(USBCMD);
	cmd_reg &= (~USBCMD_REG_HC_RUN);

	/* Stop the controller */
	Set_OpReg16(USBCMD, cmd_reg);

	/* Reset the host controller */
	Set_OpReg16(USBCMD, USBCMD_REG_GBL_RESET);

	/* Wait 10ms for reset to complete */
	mutex_exit(&uhcip->uhci_int_mutex);
	delay(drv_usectohz(UHCI_RESET_DELAY));
	mutex_enter(&uhcip->uhci_int_mutex);

	Set_OpReg16(USBCMD, 0);

	/* Set the frame number to zero */
	Set_OpReg16(FRNUM, 0);

	if (uhcip->uhci_hc_soft_state == UHCI_CTLR_INIT_STATE) {
		/* Initialize the Frame list base address area */
		if (uhci_init_frame_lst_table(dip, uhcip) != USB_SUCCESS) {
			mutex_exit(&uhcip->uhci_int_mutex);

			return (USB_FAILURE);
		}
	}

	/* Save the contents of the Frame Interval Registers */
	uhcip->uhci_frame_interval = Get_OpReg8(SOFMOD);

	frame_base_addr = uhcip->uhci_flt_cookie.dmac_address;

	/* Set the Frame list base address */
	Set_OpReg32(FRBASEADD, frame_base_addr);

	/*
	 * Begin sending SOFs
	 * Set the Host Controller Functional State to Operational
	 */
	cmd_reg = Get_OpReg16(USBCMD);
	cmd_reg |= (USBCMD_REG_HC_RUN | USBCMD_REG_MAXPKT_64 |
	    USBCMD_REG_CONFIG_FLAG);

	Set_OpReg16(USBCMD, cmd_reg);

	/*
	 * Verify the Command and interrupt enable registers,
	 * a sanity check whether actually initialized or not
	 */
	cmd_reg = Get_OpReg16(USBCMD);

	if (!(cmd_reg & (USBCMD_REG_HC_RUN | USBCMD_REG_MAXPKT_64 |
	    USBCMD_REG_CONFIG_FLAG))) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_init_ctlr: Controller initialization failed");
		mutex_exit(&uhcip->uhci_int_mutex);

		return (USB_FAILURE);
	}

	/*
	 * Set the ioc bit of the isoc intr td. This enables
	 * the generation of an interrupt for every 1024 frames.
	 */
	SetTD_ioc(uhcip, uhcip->uhci_isoc_td, 1);

	/* Set host controller soft state to operational */
	uhcip->uhci_hc_soft_state = UHCI_CTLR_OPERATIONAL_STATE;
	mutex_exit(&uhcip->uhci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_init_ctlr: Completed");

	return (USB_SUCCESS);
}


/*
 * uhci_uninit_ctlr:
 *	uninitialize the Host Controller (HC).
 */
void
uhci_uninit_ctlr(uhci_state_t *uhcip)
{
	if (uhcip->uhci_regs_handle) {
		/* Disable all the interrupts. */
		Set_OpReg16(USBINTR, DISABLE_ALL_INTRS);

		/* Complete the current transaction and then halt. */
		Set_OpReg16(USBCMD, 0);

		/* Wait for sometime */
		mutex_exit(&uhcip->uhci_int_mutex);
		delay(drv_usectohz(UHCI_TIMEWAIT));
		mutex_enter(&uhcip->uhci_int_mutex);
	}
}


/*
 * uhci_map_regs:
 *	The Host Controller (HC) contains a set of on-chip operational
 *	registers and which should be mapped into a non-cacheable
 *	portion of the system addressable space.
 */
int
uhci_map_regs(uhci_state_t *uhcip)
{
	dev_info_t		*dip = uhcip->uhci_dip;
	int			index;
	uint32_t		regs_prop_len;
	int32_t			*regs_list;
	uint16_t		command_reg;
	ddi_device_acc_attr_t	attr;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl, "uhci_map_regs:");

	/* The host controller will be little endian */
	attr.devacc_attr_version	= DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder	= DDI_STRICTORDER_ACC;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, uhcip->uhci_dip,
	    DDI_PROP_DONTPASS, "reg", &regs_list, &regs_prop_len) !=
	    DDI_PROP_SUCCESS) {

		return (USB_FAILURE);
	}

	for (index = 0; index * 5 < regs_prop_len; index++) {
		if (regs_list[index * 5] & UHCI_PROP_MASK) {
			break;
		}
	}

	/*
	 * Deallocate the memory allocated by the ddi_prop_lookup_int_array
	 */
	ddi_prop_free(regs_list);

	if (index * 5 >= regs_prop_len) {

		return (USB_FAILURE);
	}

	/* Map in operational registers */
	if (ddi_regs_map_setup(dip, index, (caddr_t *)&uhcip->uhci_regsp,
	    0, sizeof (hc_regs_t), &attr, &uhcip->uhci_regs_handle) !=
	    DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "ddi_regs_map_setup: failed");

		return (USB_FAILURE);
	}

	if (pci_config_setup(dip, &uhcip->uhci_config_handle) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_map_regs: Config error");

		return (USB_FAILURE);
	}

	/* Make sure Memory Access Enable and Master Enable are set */
	command_reg = pci_config_get16(uhcip->uhci_config_handle,
	    PCI_CONF_COMM);
	if (!(command_reg & (PCI_COMM_MAE | PCI_COMM_ME))) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_map_regs: No MAE/ME");
	}

	command_reg |= PCI_COMM_MAE | PCI_COMM_ME;
	pci_config_put16(uhcip->uhci_config_handle, PCI_CONF_COMM, command_reg);

	/*
	 * Check whether I/O base address is configured and enabled.
	 */
	if (!(command_reg & PCI_COMM_IO)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "I/O Base address access disabled");

		return (USB_FAILURE);
	}
	/*
	 * Get the IO base address of the controller
	 */
	uhcip->uhci_iobase = (pci_config_get16(uhcip->uhci_config_handle,
	    PCI_CONF_IOBASE) & PCI_CONF_IOBASE_MASK);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_map_regs: Completed");

	return (USB_SUCCESS);
}


void
uhci_unmap_regs(uhci_state_t *uhcip)
{
	/* Unmap the UHCI registers */
	if (uhcip->uhci_regs_handle) {
		/* Reset the host controller */
		Set_OpReg16(USBCMD, USBCMD_REG_GBL_RESET);

		ddi_regs_map_free(&uhcip->uhci_regs_handle);
	}

	if (uhcip->uhci_config_handle) {
		pci_config_teardown(&uhcip->uhci_config_handle);
	}
}


/*
 * uhci_set_dma_attributes:
 *	Set the limits in the DMA attributes structure. Most of the values used
 *	in the	DMA limit structres are the default values as specified by  the
 *	Writing PCI device drivers document.
 */
void
uhci_set_dma_attributes(uhci_state_t *uhcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_set_dma_attributes:");

	/* Initialize the DMA attributes */
	uhcip->uhci_dma_attr.dma_attr_version = DMA_ATTR_V0;
	uhcip->uhci_dma_attr.dma_attr_addr_lo = 0x00000000ull;
	uhcip->uhci_dma_attr.dma_attr_addr_hi = 0xfffffff0ull;

	/* 32 bit addressing */
	uhcip->uhci_dma_attr.dma_attr_count_max = 0xffffffull;

	/*
	 * Setting the dam_att_align to 512, some times fails the
	 * binding handle. I dont know why ? But setting to 16 will
	 * be right for our case (16 byte alignment required per
	 * UHCI spec for TD descriptors).
	 */

	/* 16 byte alignment */
	uhcip->uhci_dma_attr.dma_attr_align = 0x10;

	/*
	 * Since PCI  specification is byte alignment, the
	 * burstsize field should be set to 1 for PCI devices.
	 */
	uhcip->uhci_dma_attr.dma_attr_burstsizes = 0x1;

	uhcip->uhci_dma_attr.dma_attr_minxfer	= 0x1;
	uhcip->uhci_dma_attr.dma_attr_maxxfer	= 0xffffffull;
	uhcip->uhci_dma_attr.dma_attr_seg	= 0xffffffffull;
	uhcip->uhci_dma_attr.dma_attr_sgllen	= 1;
	uhcip->uhci_dma_attr.dma_attr_granular	= 1;
	uhcip->uhci_dma_attr.dma_attr_flags	= 0;
}


uint_t
pow_2(uint_t x)
{
	return ((x == 0) ? 1 : (1 << x));
}


uint_t
log_2(uint_t x)
{
	int ret_val = 0;

	while (x != 1) {
		ret_val++;
		x = x >> 1;
	}

	return (ret_val);
}


/*
 * uhci_obtain_state:
 */
uhci_state_t *
uhci_obtain_state(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	uhci_state_t *state = ddi_get_soft_state(uhci_statep, instance);

	ASSERT(state != NULL);

	return (state);
}


/*
 * uhci_alloc_hcdi_ops:
 *	The HCDI interfaces or entry points are the software interfaces used by
 *	the Universal Serial Bus Driver  (USBA) to  access the services of the
 *	Host Controller Driver (HCD).  During HCD initialization, inform  USBA
 *	about all available HCDI interfaces or entry points.
 */
usba_hcdi_ops_t *
uhci_alloc_hcdi_ops(uhci_state_t *uhcip)
{
	usba_hcdi_ops_t	*hcdi_ops;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_alloc_hcdi_ops:");

	hcdi_ops = usba_alloc_hcdi_ops();

	hcdi_ops->usba_hcdi_ops_version = HCDI_OPS_VERSION_1;

	hcdi_ops->usba_hcdi_pipe_open = uhci_hcdi_pipe_open;
	hcdi_ops->usba_hcdi_pipe_close	= uhci_hcdi_pipe_close;
	hcdi_ops->usba_hcdi_pipe_reset = uhci_hcdi_pipe_reset;
	hcdi_ops->usba_hcdi_pipe_reset_data_toggle =
	    uhci_hcdi_pipe_reset_data_toggle;

	hcdi_ops->usba_hcdi_pipe_ctrl_xfer = uhci_hcdi_pipe_ctrl_xfer;
	hcdi_ops->usba_hcdi_pipe_bulk_xfer = uhci_hcdi_pipe_bulk_xfer;
	hcdi_ops->usba_hcdi_pipe_intr_xfer = uhci_hcdi_pipe_intr_xfer;
	hcdi_ops->usba_hcdi_pipe_isoc_xfer = uhci_hcdi_pipe_isoc_xfer;

	hcdi_ops->usba_hcdi_bulk_transfer_size = uhci_hcdi_bulk_transfer_size;
	hcdi_ops->usba_hcdi_pipe_stop_intr_polling =
	    uhci_hcdi_pipe_stop_intr_polling;
	hcdi_ops->usba_hcdi_pipe_stop_isoc_polling =
	    uhci_hcdi_pipe_stop_isoc_polling;

	hcdi_ops->usba_hcdi_get_current_frame_number =
	    uhci_hcdi_get_current_frame_number;
	hcdi_ops->usba_hcdi_get_max_isoc_pkts = uhci_hcdi_get_max_isoc_pkts;

	hcdi_ops->usba_hcdi_console_input_init = uhci_hcdi_polled_input_init;
	hcdi_ops->usba_hcdi_console_input_enter = uhci_hcdi_polled_input_enter;
	hcdi_ops->usba_hcdi_console_read = uhci_hcdi_polled_read;
	hcdi_ops->usba_hcdi_console_input_exit = uhci_hcdi_polled_input_exit;
	hcdi_ops->usba_hcdi_console_input_fini = uhci_hcdi_polled_input_fini;

	hcdi_ops->usba_hcdi_console_output_init = uhci_hcdi_polled_output_init;
	hcdi_ops->usba_hcdi_console_output_enter =
	    uhci_hcdi_polled_output_enter;
	hcdi_ops->usba_hcdi_console_write = uhci_hcdi_polled_write;
	hcdi_ops->usba_hcdi_console_output_exit = uhci_hcdi_polled_output_exit;
	hcdi_ops->usba_hcdi_console_output_fini = uhci_hcdi_polled_output_fini;

	return (hcdi_ops);
}


/*
 * uhci_init_frame_lst_table :
 *	Allocate the system memory and initialize Host Controller
 *	Frame list table area The starting of the Frame list Table
 *	area must be 4096 byte aligned.
 */
static int
uhci_init_frame_lst_table(dev_info_t *dip, uhci_state_t *uhcip)
{
	int			result;
	uint_t			ccount;
	size_t			real_length;
	ddi_device_acc_attr_t	dev_attr;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_init_frame_lst_table:");

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* 4K alignment required */
	uhcip->uhci_dma_attr.dma_attr_align = 0x1000;

	/* Create space for the HCCA block */
	if (ddi_dma_alloc_handle(dip, &uhcip->uhci_dma_attr, DDI_DMA_SLEEP,
	    0, &uhcip->uhci_flt_dma_handle) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	/* Reset to default 16 bytes */
	uhcip->uhci_dma_attr.dma_attr_align = 0x10;

	if (ddi_dma_mem_alloc(uhcip->uhci_flt_dma_handle,
	    SIZE_OF_FRAME_LST_TABLE, &dev_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, (caddr_t *)&uhcip->uhci_frame_lst_tablep,
	    &real_length, &uhcip->uhci_flt_mem_handle)) {

		return (USB_FAILURE);
	}

	/* Map the whole Frame list base area into the I/O address space */
	result = ddi_dma_addr_bind_handle(uhcip->uhci_flt_dma_handle,
	    NULL, (caddr_t)uhcip->uhci_frame_lst_tablep, real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &uhcip->uhci_flt_cookie, &ccount);

	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_init_frame_list_table: More than 1 cookie");

			return (USB_FAILURE);
		}
	} else {
		uhci_decode_ddi_dma_addr_bind_handle_result(uhcip, result);

		return (USB_FAILURE);
	}

	uhcip->uhci_dma_addr_bind_flag |= UHCI_FLA_POOL_BOUND;

	bzero((void *)uhcip->uhci_frame_lst_tablep, real_length);

	/* Initialize the interrupt lists */
	uhci_build_interrupt_lattice(uhcip);

	return (USB_SUCCESS);
}


/*
 * uhci_alloc_queue_head:
 *	Allocate a queue head
 */
queue_head_t *
uhci_alloc_queue_head(uhci_state_t *uhcip)
{
	int		index;
	uhci_td_t	*dummy_td;
	queue_head_t	*queue_head;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_alloc_queue_head");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Allocate a dummy td first. */
	if ((dummy_td = uhci_allocate_td_from_pool(uhcip)) == NULL) {

		USB_DPRINTF_L2(PRINT_MASK_ALLOC,  uhcip->uhci_log_hdl,
		    "uhci_alloc_queue_head: allocate td from pool failed");

		return (NULL);
	}

	/*
	 * The first 63 queue heads in the Queue Head (QH)
	 * buffer pool are reserved for building interrupt lattice
	 * tree. Search for a blank Queue head in the QH buffer pool.
	 */
	for (index = NUM_STATIC_NODES; index < uhci_qh_pool_size; index++) {
		if (uhcip->uhci_qh_pool_addr[index].qh_flag ==
		    QUEUE_HEAD_FLAG_FREE) {
			break;
		}
	}

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_alloc_queue_head: Allocated %d", index);

	if (index == uhci_qh_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC,  uhcip->uhci_log_hdl,
		    "uhci_alloc_queue_head: All QH exhausted");

		/* Free the dummy td allocated for this qh. */
		dummy_td->flag = TD_FLAG_FREE;

		return (NULL);
	}

	queue_head = &uhcip->uhci_qh_pool_addr[index];
	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_alloc_queue_head: Allocated address 0x%p",
	    (void *)queue_head);

	bzero((void *)queue_head, sizeof (queue_head_t));
	SetQH32(uhcip, queue_head->link_ptr, HC_END_OF_LIST);
	SetQH32(uhcip, queue_head->element_ptr, HC_END_OF_LIST);
	queue_head->prev_qh	= NULL;
	queue_head->qh_flag	= QUEUE_HEAD_FLAG_BUSY;

	bzero((char *)dummy_td, sizeof (uhci_td_t));
	queue_head->td_tailp	= dummy_td;
	SetQH32(uhcip, queue_head->element_ptr, TD_PADDR(dummy_td));

	return (queue_head);
}


/*
 * uhci_allocate_bandwidth:
 *	Figure out whether or not this interval may be supported. Return
 *	the index into the  lattice if it can be supported.  Return
 *	allocation failure if it can not be supported.
 */
int
uhci_allocate_bandwidth(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*pipe_handle,
	uint_t			*node)
{
	int		bandwidth;	/* Requested bandwidth */
	uint_t		min, min_index;
	uint_t		i;
	uint_t		height;		/* Bandwidth's height in the tree */
	uint_t		leftmost;
	uint_t		length;
	uint32_t	paddr;
	queue_head_t	*tmp_qh;
	usb_ep_descr_t	*endpoint = &pipe_handle->p_ep;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * Calculate the length in bytes of a transaction on this
	 * periodic endpoint.
	 */
	mutex_enter(&pipe_handle->p_usba_device->usb_mutex);

	length = uhci_compute_total_bandwidth(endpoint,
	    pipe_handle->p_usba_device->usb_port_status);
	mutex_exit(&pipe_handle->p_usba_device->usb_mutex);

	/*
	 * If the length in bytes plus the allocated bandwidth exceeds
	 * the maximum, return bandwidth allocation failure.
	 */
	if ((length + uhcip->uhci_bandwidth_intr_min +
	    uhcip->uhci_bandwidth_isoch_sum) > (MAX_PERIODIC_BANDWIDTH)) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_allocate_bandwidth: "
		    "Reached maximum bandwidth value and cannot allocate "
		    "bandwidth for a given Interrupt/Isoch endpoint");

		return (USB_NO_BANDWIDTH);
	}

	/*
	 * ISOC xfers are not supported at this point type
	 */
	if (UHCI_XFER_TYPE(endpoint) == USB_EP_ATTR_ISOCH) {
		uhcip->uhci_bandwidth_isoch_sum += length;

		return (USB_SUCCESS);
	}

	/*
	 * This is an interrupt endpoint.
	 * Adjust bandwidth to be a power of 2
	 */
	mutex_enter(&pipe_handle->p_usba_device->usb_mutex);
	bandwidth = uhci_bandwidth_adjust(uhcip, endpoint,
	    pipe_handle->p_usba_device->usb_port_status);
	mutex_exit(&pipe_handle->p_usba_device->usb_mutex);

	/*
	 * If this bandwidth can't be supported,
	 * return allocation failure.
	 */
	if (bandwidth == USB_FAILURE) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_BW, uhcip->uhci_log_hdl,
	    "The new bandwidth is %d", bandwidth);

	/* Find the leaf with the smallest allocated bandwidth */
	min_index = 0;
	min = uhcip->uhci_bandwidth[0];

	for (i = 1; i < NUM_FRAME_LST_ENTRIES; i++) {
		if (uhcip->uhci_bandwidth[i] < min) {
			min_index = i;
			min = uhcip->uhci_bandwidth[i];
		}
	}

	USB_DPRINTF_L3(PRINT_MASK_BW, uhcip->uhci_log_hdl,
	    "The leaf with minimal bandwidth %d, "
	    "The smallest bandwidth %d", min_index, min);

	/*
	 * Find the index into the lattice given the
	 * leaf with the smallest allocated bandwidth.
	 */
	height = uhci_lattice_height(bandwidth);
	USB_DPRINTF_L3(PRINT_MASK_BW, uhcip->uhci_log_hdl,
	    "The height is %d", height);

	*node = uhci_tree_bottom_nodes[min_index];

	/* check if there are isocs TDs scheduled for this frame */
	if (uhcip->uhci_isoc_q_tailp[*node]) {
		paddr = (uhcip->uhci_isoc_q_tailp[*node]->link_ptr &
		    FRAME_LST_PTR_MASK);
	} else {
		paddr = (uhcip->uhci_frame_lst_tablep[*node] &
		    FRAME_LST_PTR_MASK);
	}

	tmp_qh = QH_VADDR(paddr);
	*node = tmp_qh->node;
	for (i = 0; i < height; i++) {
		*node = uhci_lattice_parent(*node);
	}

	USB_DPRINTF_L3(PRINT_MASK_BW, uhcip->uhci_log_hdl,
	    "The real node is %d", *node);

	/*
	 * Find the leftmost leaf in the subtree specified by the node.
	 */
	leftmost = uhci_leftmost_leaf(*node, height);
	USB_DPRINTF_L3(PRINT_MASK_BW, uhcip->uhci_log_hdl,
	    "Leftmost %d", leftmost);

	for (i = leftmost; i < leftmost +
	    (NUM_FRAME_LST_ENTRIES/bandwidth); i ++) {

		if ((length + uhcip->uhci_bandwidth_isoch_sum +
		    uhcip->uhci_bandwidth[i]) > MAX_PERIODIC_BANDWIDTH) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_allocate_bandwidth: "
			    "Reached maximum bandwidth value and cannot "
			    "allocate bandwidth for Interrupt endpoint");

			return (USB_NO_BANDWIDTH);
		}
	}

	/*
	 * All the leaves for this node must be updated with the bandwidth.
	 */
	for (i = leftmost; i < leftmost +
	    (NUM_FRAME_LST_ENTRIES/bandwidth); i ++) {
		uhcip->uhci_bandwidth[i] += length;
	}

	/* Find the leaf with the smallest allocated bandwidth */
	min_index = 0;
	min = uhcip->uhci_bandwidth[0];

	for (i = 1; i < NUM_FRAME_LST_ENTRIES; i++) {
		if (uhcip->uhci_bandwidth[i] < min) {
			min_index = i;
			min = uhcip->uhci_bandwidth[i];
		}
	}

	/* Save the minimum for later use */
	uhcip->uhci_bandwidth_intr_min = min;

	return (USB_SUCCESS);
}


/*
 * uhci_deallocate_bandwidth:
 *	Deallocate bandwidth for the given node in the lattice
 *	and the length of transfer.
 */
void
uhci_deallocate_bandwidth(uhci_state_t *uhcip,
    usba_pipe_handle_data_t *pipe_handle)
{
	uint_t		bandwidth;
	uint_t		height;
	uint_t		leftmost;
	uint_t		i;
	uint_t		min;
	usb_ep_descr_t	*endpoint = &pipe_handle->p_ep;
	uint_t		node, length;
	uhci_pipe_private_t *pp =
	    (uhci_pipe_private_t *)pipe_handle->p_hcd_private;

	/* This routine is protected by the uhci_int_mutex */
	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Obtain the length */
	mutex_enter(&pipe_handle->p_usba_device->usb_mutex);
	length = uhci_compute_total_bandwidth(endpoint,
	    pipe_handle->p_usba_device->usb_port_status);
	mutex_exit(&pipe_handle->p_usba_device->usb_mutex);

	/*
	 * If this is an isochronous endpoint, just delete endpoint's
	 * bandwidth from the total allocated isochronous bandwidth.
	 */
	if (UHCI_XFER_TYPE(endpoint) == USB_EP_ATTR_ISOCH) {
		uhcip->uhci_bandwidth_isoch_sum -= length;

		return;
	}

	/* Obtain the node */
	node = pp->pp_node;

	/* Adjust bandwidth to be a power of 2 */
	mutex_enter(&pipe_handle->p_usba_device->usb_mutex);
	bandwidth = uhci_bandwidth_adjust(uhcip, endpoint,
	    pipe_handle->p_usba_device->usb_port_status);
	mutex_exit(&pipe_handle->p_usba_device->usb_mutex);

	/* Find the height in the tree */
	height = uhci_lattice_height(bandwidth);

	/*
	 * Find the leftmost leaf in the subtree specified by the node
	 */
	leftmost = uhci_leftmost_leaf(node, height);

	/* Delete the bandwith from the appropriate lists */
	for (i = leftmost; i < leftmost + (NUM_FRAME_LST_ENTRIES/bandwidth);
	    i ++) {
		uhcip->uhci_bandwidth[i] -= length;
	}

	min = uhcip->uhci_bandwidth[0];

	/* Recompute the minimum */
	for (i = 1; i < NUM_FRAME_LST_ENTRIES; i++) {
		if (uhcip->uhci_bandwidth[i] < min) {
			min = uhcip->uhci_bandwidth[i];
		}
	}

	/* Save the minimum for later use */
	uhcip->uhci_bandwidth_intr_min = min;
}


/*
 * uhci_compute_total_bandwidth:
 *
 * Given a periodic endpoint (interrupt or isochronous) determine the total
 * bandwidth for one transaction. The UHCI host controller traverses the
 * endpoint descriptor lists on a first-come-first-serve basis. When the HC
 * services an endpoint, only a single transaction attempt is made. The  HC
 * moves to the next Endpoint Descriptor after the first transaction attempt
 * rather than finishing the entire Transfer Descriptor. Therefore, when  a
 * Transfer Descriptor is inserted into the lattice, we will only count the
 * number of bytes for one transaction.
 *
 * The following are the formulas used for calculating bandwidth in terms
 * bytes and it is for the single USB full speed and low speed	transaction
 * respectively. The protocol overheads will be different for each of  type
 * of USB transfer and all these formulas & protocol overheads are  derived
 * from the 5.9.3 section of USB Specification & with the help of Bandwidth
 * Analysis white paper which is posted on the USB  developer forum.
 *
 * Full-Speed:
 *	  Protocol overhead  + ((MaxPacketSize * 7)/6 )  + Host_Delay
 *
 * Low-Speed:
 *		Protocol overhead  + Hub LS overhead +
 *		  (Low-Speed clock * ((MaxPacketSize * 7)/6 )) + Host_Delay
 */
static uint_t
uhci_compute_total_bandwidth(usb_ep_descr_t *endpoint,
		usb_port_status_t port_status)
{
	uint_t		bandwidth;
	ushort_t	MaxPacketSize = endpoint->wMaxPacketSize;

	/* Add Host Controller specific delay to required bandwidth */
	bandwidth = HOST_CONTROLLER_DELAY;

	/* Add bit-stuffing overhead */
	MaxPacketSize = (ushort_t)((MaxPacketSize * 7) / 6);

	/* Low Speed interrupt transaction */
	if (port_status == USBA_LOW_SPEED_DEV) {
		/* Low Speed interrupt transaction */
		bandwidth += (LOW_SPEED_PROTO_OVERHEAD +
		    HUB_LOW_SPEED_PROTO_OVERHEAD +
		    (LOW_SPEED_CLOCK * MaxPacketSize));
	} else {
		/* Full Speed transaction */
		bandwidth += MaxPacketSize;

		if (UHCI_XFER_TYPE(endpoint) == USB_EP_ATTR_INTR) {
			/* Full Speed interrupt transaction */
			bandwidth += FS_NON_ISOC_PROTO_OVERHEAD;
		} else {
			/* Isochronus and input transaction */
			if (UHCI_XFER_DIR(endpoint) == USB_EP_DIR_IN) {
				bandwidth += FS_ISOC_INPUT_PROTO_OVERHEAD;
			} else {
				/* Isochronus and output transaction */
				bandwidth += FS_ISOC_OUTPUT_PROTO_OVERHEAD;
			}
		}
	}

	return (bandwidth);
}


/*
 * uhci_bandwidth_adjust:
 */
static int
uhci_bandwidth_adjust(
	uhci_state_t		*uhcip,
	usb_ep_descr_t		*endpoint,
	usb_port_status_t	port_status)
{
	int	i = 0;
	uint_t	interval;

	/*
	 * Get the polling interval from the endpoint descriptor
	 */
	interval = endpoint->bInterval;

	/*
	 * The bInterval value in the endpoint descriptor can range
	 * from 1 to 255ms. The interrupt lattice has 32 leaf nodes,
	 * and the host controller cycles through these nodes every
	 * 32ms. The longest polling  interval that the  controller
	 * supports is 32ms.
	 */

	/*
	 * Return an error if the polling interval is less than 1ms
	 * and greater than 255ms
	 */
	if ((interval < MIN_POLL_INTERVAL) || (interval > MAX_POLL_INTERVAL)) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_bandwidth_adjust: Endpoint's poll interval must be "
		    "between %d and %d ms", MIN_POLL_INTERVAL,
		    MAX_POLL_INTERVAL);

		return (USB_FAILURE);
	}

	/*
	 * According USB Specifications, a  full-speed endpoint can
	 * specify a desired polling interval 1ms to 255ms and a low
	 * speed  endpoints are limited to  specifying only 10ms to
	 * 255ms. But some old keyboards & mice uses polling interval
	 * of 8ms. For compatibility  purpose, we are using polling
	 * interval between 8ms & 255ms for low speed endpoints.
	 */
	if ((port_status == USBA_LOW_SPEED_DEV) &&
	    (interval < MIN_LOW_SPEED_POLL_INTERVAL)) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_bandwidth_adjust: Low speed endpoint's poll interval "
		    "must be >= %d ms, adjusted",
		    MIN_LOW_SPEED_POLL_INTERVAL);

		interval = MIN_LOW_SPEED_POLL_INTERVAL;
	}

	/*
	 * If polling interval is greater than 32ms,
	 * adjust polling interval equal to 32ms.
	 */
	if (interval > 32) {
		interval = 32;
	}

	/*
	 * Find the nearest power of 2 that's less
	 * than interval.
	 */
	while ((pow_2(i)) <= interval) {
		i++;
	}

	return (pow_2((i - 1)));
}


/*
 * uhci_lattice_height:
 *	Given the requested bandwidth, find the height in the tree at
 *	which the nodes for this bandwidth fall.  The height is measured
 *	as the number of nodes from the leaf to the level specified by
 *	bandwidth The root of the tree is at height TREE_HEIGHT.
 */
static uint_t
uhci_lattice_height(uint_t bandwidth)
{
	return (TREE_HEIGHT - (log_2(bandwidth)));
}


static uint_t
uhci_lattice_parent(uint_t node)
{
	return (((node % 2) == 0) ? ((node/2) - 1) : (node/2));
}


/*
 * uhci_leftmost_leaf:
 *	Find the leftmost leaf in the subtree specified by the node.
 *	Height refers to number of nodes from the bottom of the tree
 *	to the node,  including the node.
 */
static uint_t
uhci_leftmost_leaf(uint_t node, uint_t height)
{
	node = pow_2(height + VIRTUAL_TREE_HEIGHT) * (node+1) -
	    NUM_FRAME_LST_ENTRIES;
	return (node);
}


/*
 * uhci_insert_qh:
 *	Add the Queue Head (QH) into the Host Controller's (HC)
 *	appropriate queue head list.
 */
void
uhci_insert_qh(uhci_state_t *uhcip, usba_pipe_handle_data_t *ph)
{
	uhci_pipe_private_t *pp = (uhci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_qh:");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	switch (UHCI_XFER_TYPE(&ph->p_ep)) {
	case USB_EP_ATTR_CONTROL:
		uhci_insert_ctrl_qh(uhcip, pp);
		break;
	case USB_EP_ATTR_BULK:
		uhci_insert_bulk_qh(uhcip, pp);
		break;
	case USB_EP_ATTR_INTR:
		uhci_insert_intr_qh(uhcip, pp);
		break;
	case USB_EP_ATTR_ISOCH:
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_insert_qh: Illegal request");
		break;
	}
}


/*
 * uhci_insert_ctrl_qh:
 *	Insert a control QH into the Host Controller's (HC) control QH list.
 */
static void
uhci_insert_ctrl_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	queue_head_t *qh = pp->pp_qh;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_ctrl_qh:");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	if (uhcip->uhci_ctrl_xfers_q_head == uhcip->uhci_ctrl_xfers_q_tail) {
		uhcip->uhci_ctrl_xfers_q_head->prev_qh	= UHCI_INVALID_PTR;
	}

	SetQH32(uhcip, qh->link_ptr,
	    GetQH32(uhcip, uhcip->uhci_ctrl_xfers_q_tail->link_ptr));
	qh->prev_qh = uhcip->uhci_ctrl_xfers_q_tail;
	SetQH32(uhcip, uhcip->uhci_ctrl_xfers_q_tail->link_ptr,
	    QH_PADDR(qh) | HC_QUEUE_HEAD);
	uhcip->uhci_ctrl_xfers_q_tail = qh;

}


/*
 * uhci_insert_bulk_qh:
 *	Insert a bulk QH into the Host Controller's (HC) bulk QH list.
 */
static void
uhci_insert_bulk_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	queue_head_t *qh = pp->pp_qh;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_bulk_qh:");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	if (uhcip->uhci_bulk_xfers_q_head == uhcip->uhci_bulk_xfers_q_tail) {
		uhcip->uhci_bulk_xfers_q_head->prev_qh = UHCI_INVALID_PTR;
	} else if (uhcip->uhci_bulk_xfers_q_head->link_ptr ==
	    uhcip->uhci_bulk_xfers_q_tail->link_ptr) {

		/* If there is already a loop, we should keep the loop. */
		qh->link_ptr = uhcip->uhci_bulk_xfers_q_tail->link_ptr;
	}

	qh->prev_qh = uhcip->uhci_bulk_xfers_q_tail;
	SetQH32(uhcip, uhcip->uhci_bulk_xfers_q_tail->link_ptr,
	    QH_PADDR(qh) | HC_QUEUE_HEAD);
	uhcip->uhci_bulk_xfers_q_tail = qh;
}


/*
 * uhci_insert_intr_qh:
 *	Insert a periodic Queue head i.e Interrupt queue head into the
 *	Host Controller's (HC) interrupt lattice tree.
 */
static void
uhci_insert_intr_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	uint_t		node = pp->pp_node;	/* The appropriate node was */
						/* found during the opening */
						/* of the pipe.  */
	queue_head_t	*qh = pp->pp_qh;
	queue_head_t	*next_lattice_qh, *lattice_qh;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_intr_qh:");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Find the lattice queue head */
	lattice_qh = &uhcip->uhci_qh_pool_addr[node];
	next_lattice_qh =
	    QH_VADDR(GetQH32(uhcip, lattice_qh->link_ptr) & QH_LINK_PTR_MASK);

	next_lattice_qh->prev_qh = qh;
	qh->link_ptr	= lattice_qh->link_ptr;
	qh->prev_qh	= lattice_qh;
	SetQH32(uhcip, lattice_qh->link_ptr, QH_PADDR(qh) | HC_QUEUE_HEAD);
	pp->pp_data_toggle = 0;
}


/*
 * uhci_insert_intr_td:
 *	Create a TD and a data buffer for an interrupt endpoint.
 */
int
uhci_insert_intr_td(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*req,
	usb_flags_t		flags)
{
	int			error, pipe_dir;
	uint_t			length, mps;
	uint32_t		buf_offs;
	uhci_td_t		*tmp_td;
	usb_intr_req_t		*intr_reqp;
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	uhci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_intr_td: req: 0x%p", (void *)req);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Get the interrupt pipe direction */
	pipe_dir = UHCI_XFER_DIR(&ph->p_ep);

	/* Get the current interrupt request pointer */
	if (req) {
		length = req->intr_len;
	} else {
		ASSERT(pipe_dir == USB_EP_DIR_IN);
		length = (pp->pp_client_periodic_in_reqp) ?
		    (((usb_intr_req_t *)pp->
		    pp_client_periodic_in_reqp)->intr_len) :
		    ph->p_ep.wMaxPacketSize;
	}

	/* Check the size of interrupt request */
	if (length > UHCI_MAX_TD_XFER_SIZE) {

		/* the length shouldn't exceed 8K */
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_insert_intr_td: Intr request size 0x%x is "
		    "more than 0x%x", length, UHCI_MAX_TD_XFER_SIZE);

		return (USB_INVALID_REQUEST);
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_intr_td: length: 0x%x", length);

	/* Allocate a transaction wrapper */
	if ((tw = uhci_create_transfer_wrapper(uhcip, pp, length, flags)) ==
	    NULL) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_insert_intr_td: TW allocation failed");

		return (USB_NO_RESOURCES);
	}

	/*
	 * Initialize the callback and any callback
	 * data for when the td completes.
	 */
	tw->tw_handle_td = uhci_handle_intr_td;
	tw->tw_handle_callback_value = NULL;
	tw->tw_direction = (pipe_dir == USB_EP_DIR_OUT) ?
	    PID_OUT : PID_IN;
	tw->tw_curr_xfer_reqp = (usb_opaque_t)req;

	/*
	 * If it is an Interrupt IN request and interrupt request is NULL,
	 * allocate the usb interrupt request structure for the current
	 * interrupt polling request.
	 */
	if (tw->tw_direction == PID_IN) {
		if ((error = uhci_allocate_periodic_in_resource(uhcip,
		    pp, tw, flags)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_insert_intr_td: Interrupt request structure "
			    "allocation failed");

			/* free the transfer wrapper */
			uhci_deallocate_tw(uhcip, pp, tw);

			return (error);
		}
	}

	intr_reqp = (usb_intr_req_t *)tw->tw_curr_xfer_reqp;
	ASSERT(tw->tw_curr_xfer_reqp != NULL);

	tw->tw_timeout_cnt = (intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER) ?
	    intr_reqp->intr_timeout : 0;

	/* DATA IN */
	if (tw->tw_direction == PID_IN) {
		/* Insert the td onto the queue head */
		error = uhci_insert_hc_td(uhcip, 0,
		    length, pp, tw, PID_IN, intr_reqp->intr_attributes);

		if (error != USB_SUCCESS) {

			uhci_deallocate_periodic_in_resource(uhcip, pp, tw);
			/* free the transfer wrapper */
			uhci_deallocate_tw(uhcip, pp, tw);

			return (USB_NO_RESOURCES);
		}
		tw->tw_bytes_xfered = 0;

		return (USB_SUCCESS);
	}

	if (req->intr_len) {
		/* DATA OUT */
		ASSERT(req->intr_data != NULL);

		/* Copy the data into the message */
		ddi_rep_put8(tw->tw_accesshandle, req->intr_data->b_rptr,
		    (uint8_t *)tw->tw_buf, req->intr_len, DDI_DEV_AUTOINCR);
	}

	/* set tw->tw_claim flag, so that nobody else works on this tw. */
	tw->tw_claim = UHCI_INTR_HDLR_CLAIMED;

	mps = ph->p_ep.wMaxPacketSize;
	buf_offs = 0;

	/* Insert tds onto the queue head */
	while (length > 0) {

		error = uhci_insert_hc_td(uhcip, buf_offs,
		    (length > mps) ? mps : length,
		    pp, tw, PID_OUT,
		    intr_reqp->intr_attributes);

		if (error != USB_SUCCESS) {
			/* no resource. */
			break;
		}

		if (length <= mps) {
			/* inserted all data. */
			length = 0;

		} else {

			buf_offs += mps;
			length -= mps;
		}
	}

	if (error != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
		    "uhci_insert_intr_td: allocate td failed, free resource");

		/* remove all the tds */
		while (tw->tw_hctd_head != NULL) {
			uhci_delete_td(uhcip, tw->tw_hctd_head);
		}

		tw->tw_claim = UHCI_NOT_CLAIMED;
		uhci_deallocate_tw(uhcip, pp, tw);

		return (error);
	}

	/* allow HC to xfer the tds of this tw */
	tmp_td = tw->tw_hctd_head;
	while (tmp_td != NULL) {

		SetTD_status(uhcip, tmp_td, UHCI_TD_ACTIVE);
		tmp_td = tmp_td->tw_td_next;
	}

	tw->tw_bytes_xfered = 0;
	tw->tw_claim = UHCI_NOT_CLAIMED;

	return (error);
}


/*
 * uhci_create_transfer_wrapper:
 *	Create a Transaction Wrapper (TW) for non-isoc transfer types.
 *	This involves the allocating of DMA resources.
 *
 *	For non-isoc transfers, one DMA handle and one DMA buffer are
 *	allocated per transfer. The DMA buffer may contain multiple
 *	DMA cookies and the cookies should meet certain alignment
 *	requirement to be able to fit in the multiple TDs. The alignment
 *	needs to ensure:
 *	1. the size of a cookie be larger than max TD length (0x500)
 *	2. the size of a cookie be a multiple of wMaxPacketSize of the
 *	ctrl/bulk pipes
 *
 *	wMaxPacketSize for ctrl and bulk pipes may be 8, 16, 32 or 64 bytes.
 *	So the alignment should be a multiple of 64. wMaxPacketSize for intr
 *	pipes is a little different since it only specifies the max to be
 *	64 bytes, but as long as an intr transfer is limited to max TD length,
 *	any alignment can work if the cookie size is larger than max TD length.
 *
 *	Considering the above conditions, 2K alignment is used. 4K alignment
 *	should also be fine.
 */
static uhci_trans_wrapper_t *
uhci_create_transfer_wrapper(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	size_t			length,
	usb_flags_t		usb_flags)
{
	size_t			real_length;
	uhci_trans_wrapper_t	*tw;
	ddi_device_acc_attr_t	dev_attr;
	ddi_dma_attr_t		dma_attr;
	int			kmem_flag;
	int			(*dmamem_wait)(caddr_t);
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_create_transfer_wrapper: length = 0x%lx flags = 0x%x",
	    length, usb_flags);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* isochronous pipe should not call into this function */
	if (UHCI_XFER_TYPE(&ph->p_ep) == USB_EP_ATTR_ISOCH) {

		return (NULL);
	}

	/* SLEEP flag should not be used in interrupt context */
	if (servicing_interrupt()) {
		kmem_flag = KM_NOSLEEP;
		dmamem_wait = DDI_DMA_DONTWAIT;
	} else {
		kmem_flag = KM_SLEEP;
		dmamem_wait = DDI_DMA_SLEEP;
	}

	/* Allocate space for the transfer wrapper */
	if ((tw = kmem_zalloc(sizeof (uhci_trans_wrapper_t), kmem_flag)) ==
	    NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS,  uhcip->uhci_log_hdl,
		    "uhci_create_transfer_wrapper: kmem_alloc failed");

		return (NULL);
	}

	/* zero-length packet doesn't need to allocate dma memory */
	if (length == 0) {

		goto dmadone;
	}

	/* allow sg lists for transfer wrapper dma memory */
	bcopy(&uhcip->uhci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = UHCI_DMA_ATTR_SGLLEN;
	dma_attr.dma_attr_align = UHCI_DMA_ATTR_ALIGN;

	/* Store the transfer length */
	tw->tw_length = length;

	/* Allocate the DMA handle */
	if (ddi_dma_alloc_handle(uhcip->uhci_dip, &dma_attr, dmamem_wait,
	    0, &tw->tw_dmahandle) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_create_transfer_wrapper: Alloc handle failed");
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* Allocate the memory */
	if (ddi_dma_mem_alloc(tw->tw_dmahandle, tw->tw_length, &dev_attr,
	    DDI_DMA_CONSISTENT, dmamem_wait, NULL, (caddr_t *)&tw->tw_buf,
	    &real_length, &tw->tw_accesshandle) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_create_transfer_wrapper: dma_mem_alloc fail");
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	ASSERT(real_length >= length);

	/* Bind the handle */
	if (ddi_dma_addr_bind_handle(tw->tw_dmahandle, NULL,
	    (caddr_t)tw->tw_buf, real_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    dmamem_wait, NULL, &tw->tw_cookie, &tw->tw_ncookies) !=
	    DDI_DMA_MAPPED) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_create_transfer_wrapper: Bind handle failed");
		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	tw->tw_cookie_idx = 0;
	tw->tw_dma_offs = 0;

dmadone:
	/*
	 * Only allow one wrapper to be added at a time. Insert the
	 * new transaction wrapper into the list for this pipe.
	 */
	if (pp->pp_tw_head == NULL) {
		pp->pp_tw_head = tw;
		pp->pp_tw_tail = tw;
	} else {
		pp->pp_tw_tail->tw_next = tw;
		pp->pp_tw_tail = tw;
		ASSERT(tw->tw_next == NULL);
	}

	/* Store a back pointer to the pipe private structure */
	tw->tw_pipe_private = pp;

	/* Store the transfer type - synchronous or asynchronous */
	tw->tw_flags = usb_flags;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_create_transfer_wrapper: tw = 0x%p, ncookies = %u",
	    (void *)tw, tw->tw_ncookies);

	return (tw);
}


/*
 * uhci_insert_hc_td:
 *	Insert a Transfer Descriptor (TD) on an QH.
 */
int
uhci_insert_hc_td(
	uhci_state_t		*uhcip,
	uint32_t		buffer_offset,
	size_t			hcgtd_length,
	uhci_pipe_private_t	*pp,
	uhci_trans_wrapper_t	*tw,
	uchar_t			PID,
	usb_req_attrs_t		attrs)
{
	uhci_td_t	*td, *current_dummy;
	queue_head_t	*qh = pp->pp_qh;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	if ((td = uhci_allocate_td_from_pool(uhcip)) == NULL) {

		return (USB_NO_RESOURCES);
	}

	current_dummy = qh->td_tailp;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_insert_hc_td: td %p, attrs = 0x%x", (void *)td, attrs);

	/*
	 * Fill in the current dummy td and
	 * add the new dummy to the end.
	 */
	uhci_fill_in_td(uhcip, td, current_dummy, buffer_offset,
	    hcgtd_length, pp, PID, attrs, tw);

	/*
	 * Allow HC hardware xfer the td, except interrupt out td.
	 */
	if ((tw->tw_handle_td != uhci_handle_intr_td) || (PID != PID_OUT)) {

		SetTD_status(uhcip, current_dummy, UHCI_TD_ACTIVE);
	}

	/* Insert this td onto the tw */

	if (tw->tw_hctd_head == NULL) {
		ASSERT(tw->tw_hctd_tail == NULL);
		tw->tw_hctd_head = current_dummy;
		tw->tw_hctd_tail = current_dummy;
	} else {
		/* Add the td to the end of the list */
		tw->tw_hctd_tail->tw_td_next = current_dummy;
		tw->tw_hctd_tail = current_dummy;
	}

	/*
	 * Insert the TD on to the QH. When this occurs,
	 * the Host Controller will see the newly filled in TD
	 */
	current_dummy->outst_td_next	 = NULL;
	current_dummy->outst_td_prev	 = uhcip->uhci_outst_tds_tail;
	if (uhcip->uhci_outst_tds_head == NULL) {
		uhcip->uhci_outst_tds_head = current_dummy;
	} else {
		uhcip->uhci_outst_tds_tail->outst_td_next = current_dummy;
	}
	uhcip->uhci_outst_tds_tail = current_dummy;
	current_dummy->tw = tw;

	return (USB_SUCCESS);
}


/*
 * uhci_fill_in_td:
 *	Fill in the fields of a Transfer Descriptor (TD).
 */
static void
uhci_fill_in_td(
	uhci_state_t		*uhcip,
	uhci_td_t		*td,
	uhci_td_t		*current_dummy,
	uint32_t		buffer_offset,
	size_t			length,
	uhci_pipe_private_t	*pp,
	uchar_t			PID,
	usb_req_attrs_t		attrs,
	uhci_trans_wrapper_t	*tw)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uint32_t		buf_addr;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_fill_in_td: td 0x%p buf_offs 0x%x len 0x%lx "
	    "attrs 0x%x", (void *)td, buffer_offset, length, attrs);

	/*
	 * If this is an isochronous TD, just return
	 */
	if (UHCI_XFER_TYPE(&ph->p_ep) == USB_EP_ATTR_ISOCH) {

		return;
	}

	/* The maximum transfer length of UHCI cannot exceed 0x500 bytes */
	ASSERT(length <= UHCI_MAX_TD_XFER_SIZE);

	bzero((char *)td, sizeof (uhci_td_t));	/* Clear the TD */
	SetTD32(uhcip, current_dummy->link_ptr, TD_PADDR(td));

	if (attrs & USB_ATTRS_SHORT_XFER_OK) {
		SetTD_spd(uhcip, current_dummy, 1);
	}

	mutex_enter(&ph->p_usba_device->usb_mutex);
	if (ph->p_usba_device->usb_port_status == USBA_LOW_SPEED_DEV) {
		SetTD_ls(uhcip, current_dummy, LOW_SPEED_DEVICE);
	}

	SetTD_c_err(uhcip, current_dummy, UHCI_MAX_ERR_COUNT);
	SetTD_mlen(uhcip, current_dummy,
	    (length == 0) ? ZERO_LENGTH : (length - 1));
	SetTD_dtogg(uhcip, current_dummy, pp->pp_data_toggle);

	/* Adjust the data toggle bit */
	ADJ_DATA_TOGGLE(pp);

	SetTD_devaddr(uhcip, current_dummy,  ph->p_usba_device->usb_addr);
	SetTD_endpt(uhcip, current_dummy,
	    ph->p_ep.bEndpointAddress & END_POINT_ADDRESS_MASK);
	SetTD_PID(uhcip, current_dummy, PID);
	SetTD_ioc(uhcip, current_dummy, INTERRUPT_ON_COMPLETION);

	buf_addr = uhci_get_tw_paddr_by_offs(uhcip, buffer_offset, length, tw);
	SetTD32(uhcip, current_dummy->buffer_address, buf_addr);

	td->qh_td_prev			= current_dummy;
	current_dummy->qh_td_prev	= NULL;
	pp->pp_qh->td_tailp		= td;
	mutex_exit(&ph->p_usba_device->usb_mutex);
}

/*
 * uhci_get_tw_paddr_by_offs:
 *	Walk through the DMA cookies of a TW buffer to retrieve
 *	the device address used for a TD.
 *
 * buffer_offset - the starting offset into the TW buffer, where the
 *		   TD should transfer from. When a TW has more than
 *		   one TD, the TDs must be filled in increasing order.
 */
static uint32_t
uhci_get_tw_paddr_by_offs(
	uhci_state_t		*uhcip,
	uint32_t		buffer_offset,
	size_t			length,
	uhci_trans_wrapper_t	*tw)
{
	uint32_t		buf_addr;
	int			rem_len;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_get_tw_paddr_by_offs: buf_offs 0x%x len 0x%lx",
	    buffer_offset, length);

	/*
	 * TDs must be filled in increasing DMA offset order.
	 * tw_dma_offs is initialized to be 0 at TW creation and
	 * is only increased in this function.
	 */
	ASSERT(length == 0 || buffer_offset >= tw->tw_dma_offs);

	if (length == 0) {
		buf_addr = 0;

		return (buf_addr);
	}

	/*
	 * Advance to the next DMA cookie until finding the cookie
	 * that buffer_offset falls in.
	 * It is very likely this loop will never repeat more than
	 * once. It is here just to accommodate the case buffer_offset
	 * is increased by multiple cookies during two consecutive
	 * calls into this function. In that case, the interim DMA
	 * buffer is allowed to be skipped.
	 */
	while ((tw->tw_dma_offs + tw->tw_cookie.dmac_size) <=
	    buffer_offset) {
		/*
		 * tw_dma_offs always points to the starting offset
		 * of a cookie
		 */
		tw->tw_dma_offs += tw->tw_cookie.dmac_size;
		ddi_dma_nextcookie(tw->tw_dmahandle, &tw->tw_cookie);
		tw->tw_cookie_idx++;
		ASSERT(tw->tw_cookie_idx < tw->tw_ncookies);
	}

	/*
	 * Counting the remained buffer length to be filled in
	 * the TDs for current DMA cookie
	 */
	rem_len = (tw->tw_dma_offs + tw->tw_cookie.dmac_size) -
	    buffer_offset;

	/* Calculate the beginning address of the buffer */
	ASSERT(length <= rem_len);
	buf_addr = (buffer_offset - tw->tw_dma_offs) +
	    tw->tw_cookie.dmac_address;

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_get_tw_paddr_by_offs: dmac_addr 0x%x dmac_size "
	    "0x%lx idx %d", buf_addr, tw->tw_cookie.dmac_size,
	    tw->tw_cookie_idx);

	return (buf_addr);
}


/*
 * uhci_modify_td_active_bits:
 *	Sets active bit in all the tds of QH to INACTIVE so that
 *	the HC stops processing the TD's related to the QH.
 */
void
uhci_modify_td_active_bits(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp)
{
	uhci_td_t		*td_head;
	usb_ep_descr_t		*ept = &pp->pp_pipe_handle->p_ep;
	uhci_trans_wrapper_t	*tw_head = pp->pp_tw_head;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_modify_td_active_bits: tw head %p", (void *)tw_head);

	while (tw_head != NULL) {
		tw_head->tw_claim = UHCI_MODIFY_TD_BITS_CLAIMED;
		td_head = tw_head->tw_hctd_head;

		while (td_head) {
			if (UHCI_XFER_TYPE(ept) == USB_EP_ATTR_ISOCH) {
				SetTD_status(uhcip, td_head,
				    GetTD_status(uhcip, td_head) & TD_INACTIVE);
			} else {
				SetTD32(uhcip, td_head->link_ptr,
				    GetTD32(uhcip, td_head->link_ptr) |
				    HC_END_OF_LIST);
			}

			td_head = td_head->tw_td_next;
		}
		tw_head = tw_head->tw_next;
	}
}


/*
 * uhci_insert_ctrl_td:
 *	Create a TD and a data buffer for a control Queue Head.
 */
int
uhci_insert_ctrl_td(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t  *ph,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		flags)
{
	uhci_pipe_private_t  *pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	uhci_trans_wrapper_t *tw;
	size_t	ctrl_buf_size;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_ctrl_td: timeout: 0x%x", ctrl_reqp->ctrl_timeout);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * If we have a control data phase, make the data buffer start
	 * on the next 64-byte boundary so as to ensure the DMA cookie
	 * can fit in the multiple TDs. The buffer in the range of
	 * [SETUP_SIZE, UHCI_CTRL_EPT_MAX_SIZE) is just for padding
	 * and not to be transferred.
	 */
	if (ctrl_reqp->ctrl_wLength) {
		ctrl_buf_size = UHCI_CTRL_EPT_MAX_SIZE +
		    ctrl_reqp->ctrl_wLength;
	} else {
		ctrl_buf_size = SETUP_SIZE;
	}

	/* Allocate a transaction wrapper */
	if ((tw = uhci_create_transfer_wrapper(uhcip, pp,
	    ctrl_buf_size, flags)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_insert_ctrl_td: TW allocation failed");

		return (USB_NO_RESOURCES);
	}

	pp->pp_data_toggle = 0;

	tw->tw_curr_xfer_reqp = (usb_opaque_t)ctrl_reqp;
	tw->tw_bytes_xfered = 0;
	tw->tw_bytes_pending = ctrl_reqp->ctrl_wLength;
	tw->tw_timeout_cnt = max(UHCI_CTRL_TIMEOUT, ctrl_reqp->ctrl_timeout);

	/*
	 * Initialize the callback and any callback
	 * data for when the td completes.
	 */
	tw->tw_handle_td = uhci_handle_ctrl_td;
	tw->tw_handle_callback_value = NULL;

	if ((uhci_create_setup_pkt(uhcip, pp, tw)) != USB_SUCCESS) {
		tw->tw_ctrl_state = 0;

		/* free the transfer wrapper */
		uhci_deallocate_tw(uhcip, pp, tw);

		return (USB_NO_RESOURCES);
	}

	tw->tw_ctrl_state = SETUP;

	return (USB_SUCCESS);
}


/*
 * uhci_create_setup_pkt:
 *	create a setup packet to initiate a control transfer.
 *
 *	OHCI driver has seen the case where devices fail if there is
 *	more than one control transfer to the device within a frame.
 *	So, the UHCI ensures that only one TD will be put on the control
 *	pipe to one device (to be consistent with OHCI driver).
 */
static int
uhci_create_setup_pkt(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	uhci_trans_wrapper_t	*tw)
{
	int		sdata;
	usb_ctrl_req_t	*req = (usb_ctrl_req_t *)tw->tw_curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_create_setup_pkt: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%p",
	    req->ctrl_bmRequestType, req->ctrl_bRequest, req->ctrl_wValue,
	    req->ctrl_wIndex, req->ctrl_wLength, (void *)req->ctrl_data);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));
	ASSERT(tw != NULL);

	/* Create the first four bytes of the setup packet */
	sdata = (req->ctrl_bmRequestType | (req->ctrl_bRequest << 8) |
	    (req->ctrl_wValue << 16));
	ddi_put32(tw->tw_accesshandle, (uint_t *)tw->tw_buf, sdata);

	/* Create the second four bytes */
	sdata = (uint32_t)(req->ctrl_wIndex | (req->ctrl_wLength << 16));
	ddi_put32(tw->tw_accesshandle,
	    (uint_t *)(tw->tw_buf + sizeof (uint_t)), sdata);

	/*
	 * The TD's are placed on the QH one at a time.
	 * Once this TD is placed on the done list, the
	 * data or status phase TD will be enqueued.
	 */
	if ((uhci_insert_hc_td(uhcip, 0, SETUP_SIZE,
	    pp, tw, PID_SETUP, req->ctrl_attributes)) != USB_SUCCESS) {

		return (USB_NO_RESOURCES);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "Create_setup: pp = 0x%p, attrs = 0x%x", (void *)pp,
	    req->ctrl_attributes);

	/*
	 * If this control transfer has a data phase, record the
	 * direction. If the data phase is an OUT transaction ,
	 * copy the data into the buffer of the transfer wrapper.
	 */
	if (req->ctrl_wLength != 0) {
		/* There is a data stage.  Find the direction */
		if (req->ctrl_bmRequestType & USB_DEV_REQ_DEV_TO_HOST) {
			tw->tw_direction = PID_IN;
		} else {
			tw->tw_direction = PID_OUT;

			/* Copy the data into the buffer */
			ddi_rep_put8(tw->tw_accesshandle,
			    req->ctrl_data->b_rptr,
			    (uint8_t *)(tw->tw_buf + UHCI_CTRL_EPT_MAX_SIZE),
			    req->ctrl_wLength,
			    DDI_DEV_AUTOINCR);
		}
	}

	return (USB_SUCCESS);
}


/*
 * uhci_create_stats:
 *	Allocate and initialize the uhci kstat structures
 */
void
uhci_create_stats(uhci_state_t *uhcip)
{
	int			i;
	char			kstatname[KSTAT_STRLEN];
	char			*usbtypes[USB_N_COUNT_KSTATS] =
	    {"ctrl", "isoch", "bulk", "intr"};
	uint_t			instance = uhcip->uhci_instance;
	const char		*dname = ddi_driver_name(uhcip->uhci_dip);
	uhci_intrs_stats_t	*isp;

	if (UHCI_INTRS_STATS(uhcip) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,intrs",
		    dname, instance);
		UHCI_INTRS_STATS(uhcip) = kstat_create("usba", instance,
		    kstatname, "usb_interrupts", KSTAT_TYPE_NAMED,
		    sizeof (uhci_intrs_stats_t) / sizeof (kstat_named_t),
		    KSTAT_FLAG_PERSISTENT);

		if (UHCI_INTRS_STATS(uhcip) != NULL) {
			isp = UHCI_INTRS_STATS_DATA(uhcip);
			kstat_named_init(&isp->uhci_intrs_hc_halted,
			    "HC Halted", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_hc_process_err,
			    "HC Process Errors", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_host_sys_err,
			    "Host Sys Errors", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_resume_detected,
			    "Resume Detected", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_usb_err_intr,
			    "USB Error", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_usb_intr,
			    "USB Interrupts", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_total,
			    "Total Interrupts", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->uhci_intrs_not_claimed,
			    "Not Claimed", KSTAT_DATA_UINT64);

			UHCI_INTRS_STATS(uhcip)->ks_private = uhcip;
			UHCI_INTRS_STATS(uhcip)->ks_update = nulldev;
			kstat_install(UHCI_INTRS_STATS(uhcip));
		}
	}

	if (UHCI_TOTAL_STATS(uhcip) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,total",
		    dname, instance);
		UHCI_TOTAL_STATS(uhcip) = kstat_create("usba", instance,
		    kstatname, "usb_byte_count", KSTAT_TYPE_IO, 1,
		    KSTAT_FLAG_PERSISTENT);

		if (UHCI_TOTAL_STATS(uhcip) != NULL) {
			kstat_install(UHCI_TOTAL_STATS(uhcip));
		}
	}

	for (i = 0; i < USB_N_COUNT_KSTATS; i++) {
		if (uhcip->uhci_count_stats[i] == NULL) {
			(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,%s",
			    dname, instance, usbtypes[i]);
			uhcip->uhci_count_stats[i] = kstat_create("usba",
			    instance, kstatname, "usb_byte_count",
			    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);

			if (uhcip->uhci_count_stats[i] != NULL) {
				kstat_install(uhcip->uhci_count_stats[i]);
			}
		}
	}
}


/*
 * uhci_destroy_stats:
 *	Clean up uhci kstat structures
 */
void
uhci_destroy_stats(uhci_state_t *uhcip)
{
	int i;

	if (UHCI_INTRS_STATS(uhcip)) {
		kstat_delete(UHCI_INTRS_STATS(uhcip));
		UHCI_INTRS_STATS(uhcip) = NULL;
	}

	if (UHCI_TOTAL_STATS(uhcip)) {
		kstat_delete(UHCI_TOTAL_STATS(uhcip));
		UHCI_TOTAL_STATS(uhcip) = NULL;
	}

	for (i = 0; i < USB_N_COUNT_KSTATS; i++) {
		if (uhcip->uhci_count_stats[i]) {
			kstat_delete(uhcip->uhci_count_stats[i]);
			uhcip->uhci_count_stats[i] = NULL;
		}
	}
}


void
uhci_do_intrs_stats(uhci_state_t *uhcip, int val)
{
	if (UHCI_INTRS_STATS(uhcip) == NULL) {

		return;
	}

	UHCI_INTRS_STATS_DATA(uhcip)->uhci_intrs_total.value.ui64++;
	switch (val) {
	case USBSTS_REG_HC_HALTED:
		UHCI_INTRS_STATS_DATA(uhcip)->uhci_intrs_hc_halted.value.ui64++;
		break;
	case USBSTS_REG_HC_PROCESS_ERR:
		UHCI_INTRS_STATS_DATA(uhcip)->
		    uhci_intrs_hc_process_err.value.ui64++;
		break;
	case USBSTS_REG_HOST_SYS_ERR:
		UHCI_INTRS_STATS_DATA(uhcip)->
		    uhci_intrs_host_sys_err.value.ui64++;
		break;
	case USBSTS_REG_RESUME_DETECT:
		UHCI_INTRS_STATS_DATA(uhcip)->
		    uhci_intrs_resume_detected.value.ui64++;
		break;
	case USBSTS_REG_USB_ERR_INTR:
		UHCI_INTRS_STATS_DATA(uhcip)->
		    uhci_intrs_usb_err_intr.value.ui64++;
		break;
	case USBSTS_REG_USB_INTR:
		UHCI_INTRS_STATS_DATA(uhcip)->uhci_intrs_usb_intr.value.ui64++;
		break;
	default:
		UHCI_INTRS_STATS_DATA(uhcip)->
		    uhci_intrs_not_claimed.value.ui64++;
		break;
	}
}


void
uhci_do_byte_stats(uhci_state_t *uhcip, size_t len, uint8_t attr, uint8_t addr)
{
	uint8_t type = attr & USB_EP_ATTR_MASK;
	uint8_t dir = addr & USB_EP_DIR_MASK;

	switch (dir) {
	case USB_EP_DIR_IN:
		UHCI_TOTAL_STATS_DATA(uhcip)->reads++;
		UHCI_TOTAL_STATS_DATA(uhcip)->nread += len;
		switch (type) {
		case USB_EP_ATTR_CONTROL:
			UHCI_CTRL_STATS(uhcip)->reads++;
			UHCI_CTRL_STATS(uhcip)->nread += len;
			break;
		case USB_EP_ATTR_BULK:
			UHCI_BULK_STATS(uhcip)->reads++;
			UHCI_BULK_STATS(uhcip)->nread += len;
			break;
		case USB_EP_ATTR_INTR:
			UHCI_INTR_STATS(uhcip)->reads++;
			UHCI_INTR_STATS(uhcip)->nread += len;
			break;
		case USB_EP_ATTR_ISOCH:
			UHCI_ISOC_STATS(uhcip)->reads++;
			UHCI_ISOC_STATS(uhcip)->nread += len;
			break;
		}
		break;
	case USB_EP_DIR_OUT:
		UHCI_TOTAL_STATS_DATA(uhcip)->writes++;
		UHCI_TOTAL_STATS_DATA(uhcip)->nwritten += len;
		switch (type) {
		case USB_EP_ATTR_CONTROL:
			UHCI_CTRL_STATS(uhcip)->writes++;
			UHCI_CTRL_STATS(uhcip)->nwritten += len;
			break;
		case USB_EP_ATTR_BULK:
			UHCI_BULK_STATS(uhcip)->writes++;
			UHCI_BULK_STATS(uhcip)->nwritten += len;
			break;
		case USB_EP_ATTR_INTR:
			UHCI_INTR_STATS(uhcip)->writes++;
			UHCI_INTR_STATS(uhcip)->nwritten += len;
			break;
		case USB_EP_ATTR_ISOCH:
			UHCI_ISOC_STATS(uhcip)->writes++;
			UHCI_ISOC_STATS(uhcip)->nwritten += len;
			break;
		}
		break;
	}
}


/*
 * uhci_free_tw:
 *	Free the Transfer Wrapper (TW).
 */
void
uhci_free_tw(uhci_state_t *uhcip, uhci_trans_wrapper_t *tw)
{
	int rval, i;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl, "uhci_free_tw:");

	ASSERT(tw != NULL);

	if (tw->tw_isoc_strtlen > 0) {
		ASSERT(tw->tw_isoc_bufs != NULL);
		for (i = 0; i < tw->tw_ncookies; i++) {
			rval = ddi_dma_unbind_handle(
			    tw->tw_isoc_bufs[i].dma_handle);
			ASSERT(rval == USB_SUCCESS);
			ddi_dma_mem_free(&tw->tw_isoc_bufs[i].mem_handle);
			ddi_dma_free_handle(&tw->tw_isoc_bufs[i].dma_handle);
		}
		kmem_free(tw->tw_isoc_bufs, tw->tw_isoc_strtlen);
	} else if (tw->tw_dmahandle != NULL) {
		rval = ddi_dma_unbind_handle(tw->tw_dmahandle);
		ASSERT(rval == DDI_SUCCESS);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
	}

	kmem_free(tw, sizeof (uhci_trans_wrapper_t));
}


/*
 * uhci_deallocate_tw:
 *	Deallocate of a Transaction Wrapper (TW) and this involves
 *	the freeing of DMA resources.
 */
void
uhci_deallocate_tw(uhci_state_t *uhcip,
    uhci_pipe_private_t *pp, uhci_trans_wrapper_t *tw)
{
	uhci_trans_wrapper_t	*head;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_deallocate_tw:");

	/*
	 * If the transfer wrapper has no Host Controller (HC)
	 * Transfer Descriptors (TD) associated with it,  then
	 * remove the transfer wrapper. The transfers are done
	 * in FIFO order, so this should be the first transfer
	 * wrapper on the list.
	 */
	if (tw->tw_hctd_head != NULL) {
		ASSERT(tw->tw_hctd_tail != NULL);

		return;
	}

	ASSERT(tw->tw_hctd_tail == NULL);
	ASSERT(pp->pp_tw_head != NULL);

	/*
	 * If pp->pp_tw_head is NULL, set the tail also to NULL.
	 */
	head = pp->pp_tw_head;

	if (head == tw) {
		pp->pp_tw_head = head->tw_next;
		if (pp->pp_tw_head == NULL) {
			pp->pp_tw_tail = NULL;
		}
	} else {
		while (head->tw_next != tw)
			head = head->tw_next;
		head->tw_next = tw->tw_next;
		if (tw->tw_next == NULL) {
			pp->pp_tw_tail = head;
		}
	}
	uhci_free_tw(uhcip, tw);
}


void
uhci_delete_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	uhci_td_t		*tmp_td;
	uhci_trans_wrapper_t	*tw = td->tw;

	if ((td->outst_td_next == NULL) && (td->outst_td_prev == NULL)) {
		uhcip->uhci_outst_tds_head = NULL;
		uhcip->uhci_outst_tds_tail = NULL;
	} else if (td->outst_td_next == NULL) {
		td->outst_td_prev->outst_td_next = NULL;
		uhcip->uhci_outst_tds_tail = td->outst_td_prev;
	} else if (td->outst_td_prev == NULL) {
		td->outst_td_next->outst_td_prev = NULL;
		uhcip->uhci_outst_tds_head = td->outst_td_next;
	} else {
		td->outst_td_prev->outst_td_next = td->outst_td_next;
		td->outst_td_next->outst_td_prev = td->outst_td_prev;
	}

	tmp_td = tw->tw_hctd_head;

	if (tmp_td != td) {
		while (tmp_td->tw_td_next != td) {
			tmp_td = tmp_td->tw_td_next;
		}
		ASSERT(tmp_td);
		tmp_td->tw_td_next = td->tw_td_next;
		if (td->tw_td_next == NULL) {
			tw->tw_hctd_tail = tmp_td;
		}
	} else {
		tw->tw_hctd_head = tw->tw_hctd_head->tw_td_next;
		if (tw->tw_hctd_head == NULL) {
			tw->tw_hctd_tail = NULL;
		}
	}

	td->flag  = TD_FLAG_FREE;
}


void
uhci_remove_tds_tws(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph)
{
	usb_opaque_t		curr_reqp;
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*ept = &pp->pp_pipe_handle->p_ep;
	uhci_trans_wrapper_t	*tw_tmp;
	uhci_trans_wrapper_t	*tw_head = pp->pp_tw_head;

	while (tw_head != NULL) {
		tw_tmp = tw_head;
		tw_head = tw_head->tw_next;

		curr_reqp = tw_tmp->tw_curr_xfer_reqp;
		if (curr_reqp) {
			/* do this for control/bulk/intr */
			if ((tw_tmp->tw_direction == PID_IN) &&
			    (UHCI_XFER_TYPE(ept) == USB_EP_ATTR_INTR)) {
				uhci_deallocate_periodic_in_resource(uhcip,
				    pp, tw_tmp);
			} else {
				uhci_hcdi_callback(uhcip, pp,
				    pp->pp_pipe_handle, tw_tmp, USB_CR_FLUSHED);
			}
		} /* end of curr_reqp */

		if (tw_tmp->tw_claim != UHCI_MODIFY_TD_BITS_CLAIMED) {
			continue;
		}

		while (tw_tmp->tw_hctd_head != NULL) {
			uhci_delete_td(uhcip, tw_tmp->tw_hctd_head);
		}

		uhci_deallocate_tw(uhcip, pp, tw_tmp);
	}
}


/*
 * uhci_remove_qh:
 *	Remove the Queue Head from the Host Controller's
 *	appropriate QH list.
 */
void
uhci_remove_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	uhci_td_t	*dummy_td;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_remove_qh:");

	dummy_td = pp->pp_qh->td_tailp;
	dummy_td->flag = TD_FLAG_FREE;

	switch (UHCI_XFER_TYPE(&pp->pp_pipe_handle->p_ep)) {
	case USB_EP_ATTR_CONTROL:
		uhci_remove_ctrl_qh(uhcip, pp);
		break;
	case USB_EP_ATTR_BULK:
		uhci_remove_bulk_qh(uhcip, pp);
		break;
	case USB_EP_ATTR_INTR:
		uhci_remove_intr_qh(uhcip, pp);
		break;
	}
}


static void
uhci_remove_intr_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	queue_head_t   *qh = pp->pp_qh;
	queue_head_t   *next_lattice_qh =
	    QH_VADDR(GetQH32(uhcip, qh->link_ptr) & QH_LINK_PTR_MASK);

	qh->prev_qh->link_ptr	 = qh->link_ptr;
	next_lattice_qh->prev_qh = qh->prev_qh;
	qh->qh_flag = QUEUE_HEAD_FLAG_FREE;

}

/*
 * uhci_remove_bulk_qh:
 *	Remove a bulk QH from the Host Controller's QH list. There may be a
 *	loop for bulk QHs, we must care about this while removing a bulk QH.
 */
static void
uhci_remove_bulk_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	queue_head_t   *qh = pp->pp_qh;
	queue_head_t   *next_lattice_qh;
	uint32_t	paddr;

	paddr = (GetQH32(uhcip, qh->link_ptr) & QH_LINK_PTR_MASK);
	next_lattice_qh = (qh == uhcip->uhci_bulk_xfers_q_tail) ?
	    0 : QH_VADDR(paddr);

	if ((qh == uhcip->uhci_bulk_xfers_q_tail) &&
	    (qh->prev_qh == uhcip->uhci_bulk_xfers_q_head)) {
		SetQH32(uhcip, qh->prev_qh->link_ptr, HC_END_OF_LIST);
	} else {
		qh->prev_qh->link_ptr = qh->link_ptr;
	}

	if (next_lattice_qh == NULL) {
		uhcip->uhci_bulk_xfers_q_tail = qh->prev_qh;
	} else {
		next_lattice_qh->prev_qh = qh->prev_qh;
	}

	qh->qh_flag = QUEUE_HEAD_FLAG_FREE;

}


static void
uhci_remove_ctrl_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	queue_head_t   *qh = pp->pp_qh;
	queue_head_t   *next_lattice_qh =
	    QH_VADDR(GetQH32(uhcip, qh->link_ptr) & QH_LINK_PTR_MASK);

	qh->prev_qh->link_ptr = qh->link_ptr;
	if (next_lattice_qh->prev_qh != NULL) {
		next_lattice_qh->prev_qh = qh->prev_qh;
	} else {
		uhcip->uhci_ctrl_xfers_q_tail = qh->prev_qh;
	}

	qh->qh_flag = QUEUE_HEAD_FLAG_FREE;
}


/*
 * uhci_allocate_td_from_pool:
 *	Allocate a Transfer Descriptor (TD) from the TD buffer pool.
 */
static uhci_td_t *
uhci_allocate_td_from_pool(uhci_state_t *uhcip)
{
	int		index;
	uhci_td_t	*td;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * Search for a blank Transfer Descriptor (TD)
	 * in the TD buffer pool.
	 */
	for (index = 0; index < uhci_td_pool_size; index ++) {
		if (uhcip->uhci_td_pool_addr[index].flag == TD_FLAG_FREE) {
			break;
		}
	}

	if (index == uhci_td_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
		    "uhci_allocate_td_from_pool: TD exhausted");

		return (NULL);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, uhcip->uhci_log_hdl,
	    "uhci_allocate_td_from_pool: Allocated %d", index);

	/* Create a new dummy for the end of the TD list */
	td = &uhcip->uhci_td_pool_addr[index];

	/* Mark the newly allocated TD as a dummy */
	td->flag =  TD_FLAG_DUMMY;
	td->qh_td_prev	=  NULL;

	return (td);
}


/*
 * uhci_insert_bulk_td:
 */
int
uhci_insert_bulk_td(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_bulk_req_t		*req,
	usb_flags_t		flags)
{
	size_t			length;
	uint_t			mps;	/* MaxPacketSize */
	uint_t			num_bulk_tds, i, j;
	uint32_t		buf_offs;
	uhci_td_t		*bulk_td_ptr;
	uhci_td_t		*current_dummy, *tmp_td;
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	uhci_trans_wrapper_t	*tw;
	uhci_bulk_isoc_xfer_t	*bulk_xfer_info;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_bulk_td: req: 0x%p, flags = 0x%x", (void *)req, flags);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * Create transfer wrapper
	 */
	if ((tw = uhci_create_transfer_wrapper(uhcip, pp, req->bulk_len,
	    flags)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_insert_bulk_td: TW allocation failed");

		return (USB_NO_RESOURCES);
	}

	tw->tw_bytes_xfered		= 0;
	tw->tw_bytes_pending		= req->bulk_len;
	tw->tw_handle_td		= uhci_handle_bulk_td;
	tw->tw_handle_callback_value	= (usb_opaque_t)req->bulk_data;
	tw->tw_timeout_cnt		= req->bulk_timeout;
	tw->tw_data			= req->bulk_data;
	tw->tw_curr_xfer_reqp		= (usb_opaque_t)req;

	/* Get the bulk pipe direction */
	tw->tw_direction = (UHCI_XFER_DIR(&ph->p_ep) == USB_EP_DIR_OUT) ?
	    PID_OUT : PID_IN;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_insert_bulk_td: direction: 0x%x", tw->tw_direction);

	/* If the DATA OUT, copy the data into transfer buffer. */
	if (tw->tw_direction == PID_OUT) {
		if (req->bulk_len) {
			ASSERT(req->bulk_data != NULL);

			/* Copy the data into the message */
			ddi_rep_put8(tw->tw_accesshandle,
			    req->bulk_data->b_rptr,
			    (uint8_t *)tw->tw_buf,
			    req->bulk_len, DDI_DEV_AUTOINCR);
		}
	}

	/* Get the max packet size.  */
	length = mps = pp->pp_pipe_handle->p_ep.wMaxPacketSize;

	/*
	 * Calculate number of TD's to insert in the current frame interval.
	 * Max number TD's allowed (driver implementation) is 128
	 * in one frame interval. Once all the TD's are completed
	 * then the remaining TD's will be inserted into the lattice
	 * in the uhci_handle_bulk_td().
	 */
	if ((tw->tw_bytes_pending / mps) >= MAX_NUM_BULK_TDS_PER_XFER) {
		num_bulk_tds = MAX_NUM_BULK_TDS_PER_XFER;
	} else {
		num_bulk_tds = (tw->tw_bytes_pending / mps);

		if (tw->tw_bytes_pending % mps || tw->tw_bytes_pending == 0) {
			num_bulk_tds++;
			length = (tw->tw_bytes_pending % mps);
		}
	}

	/*
	 * Allocate memory for the bulk xfer information structure
	 */
	if ((bulk_xfer_info = kmem_zalloc(
	    sizeof (uhci_bulk_isoc_xfer_t), KM_NOSLEEP)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_insert_bulk_td: kmem_zalloc failed");

		/* Free the transfer wrapper */
		uhci_deallocate_tw(uhcip, pp, tw);

		return (USB_FAILURE);
	}

	/* Allocate memory for the bulk TD's */
	if (uhci_alloc_bulk_isoc_tds(uhcip, num_bulk_tds, bulk_xfer_info) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_insert_bulk_td: alloc_bulk_isoc_tds failed");

		kmem_free(bulk_xfer_info, sizeof (uhci_bulk_isoc_xfer_t));

		/* Free the transfer wrapper */
		uhci_deallocate_tw(uhcip, pp, tw);

		return (USB_FAILURE);
	}

	td_pool_ptr = &bulk_xfer_info->td_pools[0];
	bulk_td_ptr = (uhci_td_t *)td_pool_ptr->pool_addr;
	bulk_td_ptr[0].qh_td_prev = NULL;
	current_dummy = pp->pp_qh->td_tailp;
	buf_offs = 0;
	pp->pp_qh->bulk_xfer_info = bulk_xfer_info;

	/* Fill up all the bulk TD's */
	for (i = 0; i < bulk_xfer_info->num_pools; i++) {
		for (j = 0; j < (td_pool_ptr->num_tds - 1); j++) {
			uhci_fill_in_bulk_isoc_td(uhcip, &bulk_td_ptr[j],
			    &bulk_td_ptr[j+1], BULKTD_PADDR(td_pool_ptr,
			    &bulk_td_ptr[j+1]), ph, buf_offs, mps, tw);
			buf_offs += mps;
		}

		/* fill in the last TD */
		if (i == (bulk_xfer_info->num_pools - 1)) {
			uhci_fill_in_bulk_isoc_td(uhcip, &bulk_td_ptr[j],
			    current_dummy, TD_PADDR(current_dummy),
			    ph, buf_offs, length, tw);
		} else {
			/* fill in the TD at the tail of a pool */
			tmp_td = &bulk_td_ptr[j];
			td_pool_ptr = &bulk_xfer_info->td_pools[i + 1];
			bulk_td_ptr = (uhci_td_t *)td_pool_ptr->pool_addr;
			uhci_fill_in_bulk_isoc_td(uhcip, tmp_td,
			    &bulk_td_ptr[0], BULKTD_PADDR(td_pool_ptr,
			    &bulk_td_ptr[0]), ph, buf_offs, mps, tw);
			buf_offs += mps;
		}
	}

	bulk_xfer_info->num_tds	= (ushort_t)num_bulk_tds;

	/*
	 * Point the end of the lattice tree to the start of the bulk xfers
	 * queue head. This allows the HC to execute the same Queue Head/TD
	 * in the same frame. There are some bulk devices, which NAKs after
	 * completing each TD. As a result, the performance on such devices
	 * is very bad.  This loop will  provide a chance to execute NAk'ed
	 * bulk TDs again in the same frame.
	 */
	if (uhcip->uhci_pending_bulk_cmds++ == 0) {
		uhcip->uhci_bulk_xfers_q_tail->link_ptr =
		    uhcip->uhci_bulk_xfers_q_head->link_ptr;
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_insert_bulk_td: count = %d no tds  %d",
		    uhcip->uhci_pending_bulk_cmds, num_bulk_tds);
	}

	/* Insert on the bulk queue head for the execution by HC */
	SetQH32(uhcip, pp->pp_qh->element_ptr,
	    bulk_xfer_info->td_pools[0].cookie.dmac_address);

	return (USB_SUCCESS);
}


/*
 * uhci_fill_in_bulk_isoc_td
 *     Fills the bulk/isoc TD
 *
 * offset - different meanings for bulk and isoc TDs:
 *	    starting offset into the TW buffer for a bulk TD
 *	    and the index into the isoc packet list for an isoc TD
 */
void
uhci_fill_in_bulk_isoc_td(uhci_state_t *uhcip, uhci_td_t *current_td,
	uhci_td_t		*next_td,
	uint32_t		next_td_paddr,
	usba_pipe_handle_data_t	*ph,
	uint_t			offset,
	uint_t			length,
	uhci_trans_wrapper_t	*tw)
{
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*ept = &pp->pp_pipe_handle->p_ep;
	uint32_t		buf_addr;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_fill_in_bulk_isoc_td: tw 0x%p offs 0x%x length 0x%x",
	    (void *)tw, offset, length);

	bzero((char *)current_td, sizeof (uhci_td_t));
	SetTD32(uhcip, current_td->link_ptr, next_td_paddr | HC_DEPTH_FIRST);

	switch (UHCI_XFER_TYPE(ept)) {
	case USB_EP_ATTR_ISOCH:
		if (((usb_isoc_req_t *)tw->tw_curr_xfer_reqp)->isoc_attributes
		    & USB_ATTRS_SHORT_XFER_OK) {
			SetTD_spd(uhcip, current_td, 1);
		}
		break;
	case USB_EP_ATTR_BULK:
		if (((usb_bulk_req_t *)tw->tw_curr_xfer_reqp)->bulk_attributes
		    & USB_ATTRS_SHORT_XFER_OK) {
			SetTD_spd(uhcip, current_td, 1);
		}
		break;
	}

	mutex_enter(&ph->p_usba_device->usb_mutex);

	SetTD_c_err(uhcip, current_td, UHCI_MAX_ERR_COUNT);
	SetTD_status(uhcip, current_td, UHCI_TD_ACTIVE);
	SetTD_ioc(uhcip, current_td, INTERRUPT_ON_COMPLETION);
	SetTD_mlen(uhcip, current_td,
	    (length == 0) ? ZERO_LENGTH : (length - 1));
	SetTD_dtogg(uhcip, current_td, pp->pp_data_toggle);
	SetTD_devaddr(uhcip, current_td, ph->p_usba_device->usb_addr);
	SetTD_endpt(uhcip, current_td, ph->p_ep.bEndpointAddress &
	    END_POINT_ADDRESS_MASK);
	SetTD_PID(uhcip, current_td, tw->tw_direction);

	/* Get the right buffer address for the current TD */
	switch (UHCI_XFER_TYPE(ept)) {
	case USB_EP_ATTR_ISOCH:
		buf_addr = tw->tw_isoc_bufs[offset].cookie.dmac_address;
		break;
	case USB_EP_ATTR_BULK:
		buf_addr = uhci_get_tw_paddr_by_offs(uhcip, offset,
		    length, tw);
		break;
	}
	SetTD32(uhcip, current_td->buffer_address, buf_addr);

	/*
	 * Adjust the data toggle.
	 * The data toggle bit must always be 0 for isoc transfers.
	 * And set the "iso" bit in the TD for isoc transfers.
	 */
	if (UHCI_XFER_TYPE(ept) == USB_EP_ATTR_ISOCH) {
		pp->pp_data_toggle = 0;
		SetTD_iso(uhcip, current_td, 1);
	} else {
		ADJ_DATA_TOGGLE(pp);
		next_td->qh_td_prev = current_td;
		pp->pp_qh->td_tailp = next_td;
	}

	current_td->outst_td_next = NULL;
	current_td->outst_td_prev = uhcip->uhci_outst_tds_tail;
	if (uhcip->uhci_outst_tds_head == NULL) {
		uhcip->uhci_outst_tds_head = current_td;
	} else {
		uhcip->uhci_outst_tds_tail->outst_td_next = current_td;
	}
	uhcip->uhci_outst_tds_tail = current_td;
	current_td->tw = tw;

	if (tw->tw_hctd_head == NULL) {
		ASSERT(tw->tw_hctd_tail == NULL);
		tw->tw_hctd_head = current_td;
		tw->tw_hctd_tail = current_td;
	} else {
		/* Add the td to the end of the list */
		tw->tw_hctd_tail->tw_td_next = current_td;
		tw->tw_hctd_tail = current_td;
	}

	mutex_exit(&ph->p_usba_device->usb_mutex);
}


/*
 * uhci_alloc_bulk_isoc_tds:
 *	- Allocates the isoc/bulk TD pools. It will allocate one whole
 *	  pool to store all the TDs if the system allows. Only when the
 *	  first allocation fails, it tries to allocate several small
 *	  pools with each pool limited in physical page size.
 */
static int
uhci_alloc_bulk_isoc_tds(
	uhci_state_t		*uhcip,
	uint_t			num_tds,
	uhci_bulk_isoc_xfer_t	*info)
{
	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_alloc_bulk_isoc_tds: num_tds: 0x%x info: 0x%p",
	    num_tds, (void *)info);

	info->num_pools = 1;
	/* allocate as a whole pool at the first time */
	if (uhci_alloc_memory_for_tds(uhcip, num_tds, info) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "alloc_memory_for_tds failed: num_tds %d num_pools %d",
		    num_tds, info->num_pools);

		/* reduce the td number per pool and alloc again */
		info->num_pools = num_tds / UHCI_MAX_TD_NUM_PER_POOL;
		if (num_tds % UHCI_MAX_TD_NUM_PER_POOL) {
			info->num_pools++;
		}

		if (uhci_alloc_memory_for_tds(uhcip, num_tds, info) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "alloc_memory_for_tds failed: num_tds %d "
			    "num_pools %d", num_tds, info->num_pools);

			return (USB_NO_RESOURCES);
		}
	}

	return (USB_SUCCESS);
}


/*
 * uhci_alloc_memory_for_tds:
 *	- Allocates memory for the isoc/bulk td pools.
 */
static int
uhci_alloc_memory_for_tds(
	uhci_state_t		*uhcip,
	uint_t			num_tds,
	uhci_bulk_isoc_xfer_t	*info)
{
	int			result, i, j, err;
	size_t			real_length;
	uint_t			ccount, num;
	ddi_device_acc_attr_t	dev_attr;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr1, *td_pool_ptr2;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_alloc_memory_for_tds: num_tds: 0x%x info: 0x%p "
	    "num_pools: %u", num_tds, (void *)info, info->num_pools);

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* Allocate the TD pool structures */
	if ((info->td_pools = kmem_zalloc(
	    (sizeof (uhci_bulk_isoc_td_pool_t) * info->num_pools),
	    KM_SLEEP)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_alloc_memory_for_tds: alloc td_pools failed");

		return (USB_FAILURE);
	}

	for (i = 0; i < info->num_pools; i++) {
		if (info->num_pools == 1) {
			num = num_tds;
		} else if (i < (info->num_pools - 1)) {
			num = UHCI_MAX_TD_NUM_PER_POOL;
		} else {
			num = (num_tds % UHCI_MAX_TD_NUM_PER_POOL);
		}

		td_pool_ptr1 = &info->td_pools[i];

		/* Allocate the bulk TD pool DMA handle */
		if (ddi_dma_alloc_handle(uhcip->uhci_dip,
		    &uhcip->uhci_dma_attr, DDI_DMA_SLEEP, 0,
		    &td_pool_ptr1->dma_handle) != DDI_SUCCESS) {

			for (j = 0; j < i; j++) {
				td_pool_ptr2 = &info->td_pools[j];
				result = ddi_dma_unbind_handle(
				    td_pool_ptr2->dma_handle);
				ASSERT(result == DDI_SUCCESS);
				ddi_dma_mem_free(&td_pool_ptr2->mem_handle);
				ddi_dma_free_handle(&td_pool_ptr2->dma_handle);
			}

			kmem_free(info->td_pools,
			    (sizeof (uhci_bulk_isoc_td_pool_t) *
			    info->num_pools));

			return (USB_FAILURE);
		}

		/* Allocate the memory for the bulk TD pool */
		if (ddi_dma_mem_alloc(td_pool_ptr1->dma_handle,
		    num * sizeof (uhci_td_t), &dev_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, 0,
		    &td_pool_ptr1->pool_addr, &real_length,
		    &td_pool_ptr1->mem_handle) != DDI_SUCCESS) {

			ddi_dma_free_handle(&td_pool_ptr1->dma_handle);

			for (j = 0; j < i; j++) {
				td_pool_ptr2 = &info->td_pools[j];
				result = ddi_dma_unbind_handle(
				    td_pool_ptr2->dma_handle);
				ASSERT(result == DDI_SUCCESS);
				ddi_dma_mem_free(&td_pool_ptr2->mem_handle);
				ddi_dma_free_handle(&td_pool_ptr2->dma_handle);
			}

			kmem_free(info->td_pools,
			    (sizeof (uhci_bulk_isoc_td_pool_t) *
			    info->num_pools));

			return (USB_FAILURE);
		}

		/* Map the bulk TD pool into the I/O address space */
		result = ddi_dma_addr_bind_handle(td_pool_ptr1->dma_handle,
		    NULL, (caddr_t)td_pool_ptr1->pool_addr, real_length,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		    &td_pool_ptr1->cookie, &ccount);

		/* Process the result */
		err = USB_SUCCESS;

		if (result != DDI_DMA_MAPPED) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_allocate_memory_for_tds: Result = %d",
			    result);
			uhci_decode_ddi_dma_addr_bind_handle_result(uhcip,
			    result);

			err = USB_FAILURE;
		}

		if ((result == DDI_DMA_MAPPED) && (ccount != 1)) {
			/* The cookie count should be 1 */
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uhcip->uhci_log_hdl,
			    "uhci_allocate_memory_for_tds: "
			    "More than 1 cookie");

			result = ddi_dma_unbind_handle(
			    td_pool_ptr1->dma_handle);
			ASSERT(result == DDI_SUCCESS);

			err = USB_FAILURE;
		}

		if (err == USB_FAILURE) {

			ddi_dma_mem_free(&td_pool_ptr1->mem_handle);
			ddi_dma_free_handle(&td_pool_ptr1->dma_handle);

			for (j = 0; j < i; j++) {
				td_pool_ptr2 = &info->td_pools[j];
				result = ddi_dma_unbind_handle(
				    td_pool_ptr2->dma_handle);
				ASSERT(result == DDI_SUCCESS);
				ddi_dma_mem_free(&td_pool_ptr2->mem_handle);
				ddi_dma_free_handle(&td_pool_ptr2->dma_handle);
			}

			kmem_free(info->td_pools,
			    (sizeof (uhci_bulk_isoc_td_pool_t) *
			    info->num_pools));

			return (USB_FAILURE);
		}

		bzero((void *)td_pool_ptr1->pool_addr,
		    num * sizeof (uhci_td_t));
		td_pool_ptr1->num_tds = (ushort_t)num;
	}

	return (USB_SUCCESS);
}


/*
 * uhci_handle_bulk_td:
 *
 *	Handles the completed bulk transfer descriptors
 */
void
uhci_handle_bulk_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	uint_t			num_bulk_tds, index, td_count, j;
	usb_cr_t		error;
	uint_t			length, bytes_xfered;
	ushort_t		MaxPacketSize;
	uint32_t		buf_offs, paddr;
	uhci_td_t		*bulk_td_ptr, *current_dummy, *td_head;
	uhci_td_t		*tmp_td;
	queue_head_t		*qh, *next_qh;
	uhci_trans_wrapper_t	*tw = td->tw;
	uhci_pipe_private_t	*pp = tw->tw_pipe_private;
	uhci_bulk_isoc_xfer_t	*bulk_xfer_info;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr;
	usba_pipe_handle_data_t	*ph;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_handle_bulk_td: td = 0x%p tw = 0x%p", (void *)td, (void *)tw);

	/*
	 * Update the tw_bytes_pending, and tw_bytes_xfered
	 */
	bytes_xfered = ZERO_LENGTH;

	/*
	 * Check whether there are any errors occurred in the xfer.
	 * If so, update the data_toggle for the queue head and
	 * return error to the upper layer.
	 */
	if (GetTD_status(uhcip, td) & TD_STATUS_MASK) {
		uhci_handle_bulk_td_errors(uhcip, td);

		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_handle_bulk_td: error; data toggle: 0x%x",
		    pp->pp_data_toggle);

		return;
	}

	/*
	 * Update the tw_bytes_pending, and tw_bytes_xfered
	 */
	bytes_xfered = GetTD_alen(uhcip, td);
	if (bytes_xfered != ZERO_LENGTH) {
		tw->tw_bytes_pending -= (bytes_xfered + 1);
		tw->tw_bytes_xfered  += (bytes_xfered + 1);
	}

	/*
	 * Get Bulk pipe information and pipe handle
	 */
	bulk_xfer_info	= pp->pp_qh->bulk_xfer_info;
	ph = tw->tw_pipe_private->pp_pipe_handle;

	/*
	 * Check whether data underrun occurred.
	 * If so, complete the transfer
	 * Update the data toggle bit
	 */
	if (bytes_xfered != GetTD_mlen(uhcip, td)) {
		bulk_xfer_info->num_tds = 1;
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_handle_bulk_td: Data underrun occured");

		pp->pp_data_toggle = GetTD_dtogg(uhcip, td) == 0 ? 1 : 0;
	}

	/*
	 * If the TD's in the current frame are completed, then check
	 * whether we have any more bytes to xfer. If so, insert TD's.
	 * If no more bytes needs to be transferred, then do callback to the
	 * upper layer.
	 * If the TD's in the current frame are not completed, then
	 * just delete the TD from the linked lists.
	 */
	USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_handle_bulk_td: completed TD data toggle: 0x%x",
	    GetTD_dtogg(uhcip, td));

	if (--bulk_xfer_info->num_tds == 0) {
		uhci_delete_td(uhcip, td);

		if ((tw->tw_bytes_pending) &&
		    (GetTD_mlen(uhcip, td) - GetTD_alen(uhcip, td) == 0)) {

			MaxPacketSize = pp->pp_pipe_handle->p_ep.wMaxPacketSize;
			length = MaxPacketSize;

			qh = pp->pp_qh;
			paddr = GetQH32(uhcip, qh->link_ptr) & QH_LINK_PTR_MASK;
			if (GetQH32(uhcip, qh->link_ptr) !=
			    GetQH32(uhcip,
			    uhcip->uhci_bulk_xfers_q_head->link_ptr)) {
				next_qh = QH_VADDR(paddr);
				SetQH32(uhcip, qh->prev_qh->link_ptr,
				    paddr|(0x2));
				next_qh->prev_qh = qh->prev_qh;
				SetQH32(uhcip, qh->link_ptr,
				    GetQH32(uhcip,
				    uhcip->uhci_bulk_xfers_q_head->link_ptr));
				qh->prev_qh = uhcip->uhci_bulk_xfers_q_tail;
				SetQH32(uhcip,
				    uhcip->uhci_bulk_xfers_q_tail->link_ptr,
				    QH_PADDR(qh) | 0x2);
				uhcip->uhci_bulk_xfers_q_tail = qh;
			}

			if ((tw->tw_bytes_pending / MaxPacketSize) >=
			    MAX_NUM_BULK_TDS_PER_XFER) {
				num_bulk_tds = MAX_NUM_BULK_TDS_PER_XFER;
			} else {
				num_bulk_tds =
				    (tw->tw_bytes_pending / MaxPacketSize);
				if (tw->tw_bytes_pending % MaxPacketSize) {
					num_bulk_tds++;
					length = (tw->tw_bytes_pending %
					    MaxPacketSize);
				}
			}

			current_dummy = pp->pp_qh->td_tailp;
			td_pool_ptr = &bulk_xfer_info->td_pools[0];
			bulk_td_ptr = (uhci_td_t *)td_pool_ptr->pool_addr;
			buf_offs = tw->tw_bytes_xfered;
			td_count = num_bulk_tds;
			index = 0;

			/* reuse the TDs to transfer more data */
			while (td_count > 0) {
				for (j = 0;
				    (j < (td_pool_ptr->num_tds - 1)) &&
				    (td_count > 1); j++, td_count--) {
					uhci_fill_in_bulk_isoc_td(uhcip,
					    &bulk_td_ptr[j], &bulk_td_ptr[j+1],
					    BULKTD_PADDR(td_pool_ptr,
					    &bulk_td_ptr[j+1]), ph, buf_offs,
					    MaxPacketSize, tw);
					buf_offs += MaxPacketSize;
				}

				if (td_count == 1) {
					uhci_fill_in_bulk_isoc_td(uhcip,
					    &bulk_td_ptr[j], current_dummy,
					    TD_PADDR(current_dummy), ph,
					    buf_offs, length, tw);

					break;
				} else {
					tmp_td = &bulk_td_ptr[j];
					ASSERT(index <
					    (bulk_xfer_info->num_pools - 1));
					td_pool_ptr = &bulk_xfer_info->
					    td_pools[index + 1];
					bulk_td_ptr = (uhci_td_t *)
					    td_pool_ptr->pool_addr;
					uhci_fill_in_bulk_isoc_td(uhcip,
					    tmp_td, &bulk_td_ptr[0],
					    BULKTD_PADDR(td_pool_ptr,
					    &bulk_td_ptr[0]), ph, buf_offs,
					    MaxPacketSize, tw);
					buf_offs += MaxPacketSize;
					td_count--;
					index++;
				}
			}

			pp->pp_qh->bulk_xfer_info = bulk_xfer_info;
			bulk_xfer_info->num_tds	= (ushort_t)num_bulk_tds;
			SetQH32(uhcip, pp->pp_qh->element_ptr,
			    bulk_xfer_info->td_pools[0].cookie.dmac_address);
		} else {
			usba_pipe_handle_data_t *usb_pp = pp->pp_pipe_handle;

			pp->pp_qh->bulk_xfer_info = NULL;

			if (tw->tw_bytes_pending) {
				/* Update the element pointer */
				SetQH32(uhcip, pp->pp_qh->element_ptr,
				    TD_PADDR(pp->pp_qh->td_tailp));

				/* Remove all the tds */
				td_head = tw->tw_hctd_head;
				while (td_head != NULL) {
					uhci_delete_td(uhcip, td_head);
					td_head = tw->tw_hctd_head;
				}
			}

			if (tw->tw_direction == PID_IN) {
				usb_req_attrs_t	attrs = ((usb_bulk_req_t *)
				    tw->tw_curr_xfer_reqp)->bulk_attributes;

				error = USB_CR_OK;

				/* Data run occurred */
				if (tw->tw_bytes_pending &&
				    (!(attrs & USB_ATTRS_SHORT_XFER_OK))) {
					error = USB_CR_DATA_UNDERRUN;
				}

				uhci_sendup_td_message(uhcip, error, tw);
			} else {
				uhci_do_byte_stats(uhcip, tw->tw_length,
				    usb_pp->p_ep.bmAttributes,
				    usb_pp->p_ep.bEndpointAddress);

				/* Data underrun occurred */
				if (tw->tw_bytes_pending) {

					tw->tw_data->b_rptr +=
					    tw->tw_bytes_xfered;

					USB_DPRINTF_L2(PRINT_MASK_ATTA,
					    uhcip->uhci_log_hdl,
					    "uhci_handle_bulk_td: "
					    "data underrun occurred");

					uhci_hcdi_callback(uhcip, pp,
					    tw->tw_pipe_private->pp_pipe_handle,
					    tw, USB_CR_DATA_UNDERRUN);
				} else {
					uhci_hcdi_callback(uhcip, pp,
					    tw->tw_pipe_private->pp_pipe_handle,
					    tw, USB_CR_OK);
				}
			} /* direction */

			/* Deallocate DMA memory */
			uhci_deallocate_tw(uhcip, pp, tw);
			for (j = 0; j < bulk_xfer_info->num_pools; j++) {
				td_pool_ptr = &bulk_xfer_info->td_pools[j];
				(void) ddi_dma_unbind_handle(
				    td_pool_ptr->dma_handle);
				ddi_dma_mem_free(&td_pool_ptr->mem_handle);
				ddi_dma_free_handle(&td_pool_ptr->dma_handle);
			}
			kmem_free(bulk_xfer_info->td_pools,
			    (sizeof (uhci_bulk_isoc_td_pool_t) *
			    bulk_xfer_info->num_pools));
			kmem_free(bulk_xfer_info,
			    sizeof (uhci_bulk_isoc_xfer_t));

			/*
			 * When there are no pending bulk commands, point the
			 * end of the lattice tree to NULL. This will make sure
			 * that the HC control does not loop anymore and PCI
			 * bus is not affected.
			 */
			if (--uhcip->uhci_pending_bulk_cmds == 0) {
				uhcip->uhci_bulk_xfers_q_tail->link_ptr =
				    HC_END_OF_LIST;
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    uhcip->uhci_log_hdl,
				    "uhci_handle_bulk_td: count = %d",
				    uhcip->uhci_pending_bulk_cmds);
			}
		}
	} else {
		uhci_delete_td(uhcip, td);
	}
}


void
uhci_handle_bulk_td_errors(uhci_state_t *uhcip, uhci_td_t *td)
{
	usb_cr_t		usb_err;
	uint32_t		paddr_tail, element_ptr, paddr;
	uhci_td_t		*next_td;
	uhci_pipe_private_t	*pp;
	uhci_trans_wrapper_t	*tw = td->tw;
	usba_pipe_handle_data_t	*ph;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr = NULL;

	USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_handle_bulk_td_errors: td = %p", (void *)td);

#ifdef	DEBUG
	uhci_print_td(uhcip, td);
#endif

	tw = td->tw;
	ph = tw->tw_pipe_private->pp_pipe_handle;
	pp = (uhci_pipe_private_t *)ph->p_hcd_private;

	/*
	 * Find the type of error occurred and return the error
	 * to the upper layer. And adjust the data toggle.
	 */
	element_ptr = GetQH32(uhcip, pp->pp_qh->element_ptr) &
	    QH_ELEMENT_PTR_MASK;
	paddr_tail = TD_PADDR(pp->pp_qh->td_tailp);

	/*
	 * If a timeout occurs before a transfer has completed,
	 * the timeout handler sets the CRC/Timeout bit and clears the Active
	 * bit in the link_ptr for each td in the transfer.
	 * It then waits (at least) 1 ms so that any tds the controller might
	 * have been executing will have completed.
	 * So at this point element_ptr will point to either:
	 * 1) the next td for the transfer (which has not been executed,
	 * and has the CRC/Timeout status bit set and Active bit cleared),
	 * 2) the dummy td for this qh.
	 * So if the element_ptr does not point to the dummy td, we know
	 * it points to the next td that would have been executed.
	 * That td has the data toggle we want to save.
	 * All outstanding tds have been marked as CRC/Timeout,
	 * so it doesn't matter which td we pass to uhci_parse_td_error
	 * for the error status.
	 */
	if (element_ptr != paddr_tail) {
		paddr = (element_ptr & QH_ELEMENT_PTR_MASK);
		uhci_get_bulk_td_by_paddr(uhcip, pp->pp_qh->bulk_xfer_info,
		    paddr, &td_pool_ptr);
		next_td = BULKTD_VADDR(td_pool_ptr, paddr);
		USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_handle_bulk_td_errors: next td = %p",
		    (void *)next_td);

		usb_err = uhci_parse_td_error(uhcip, pp, next_td);
	} else {
		usb_err = uhci_parse_td_error(uhcip, pp, td);
	}

	/*
	 * Update the link pointer.
	 */
	SetQH32(uhcip, pp->pp_qh->element_ptr, TD_PADDR(pp->pp_qh->td_tailp));

	/*
	 * Send up number of bytes transferred before the error condition.
	 */
	if ((tw->tw_direction == PID_OUT) && tw->tw_data) {
		tw->tw_data->b_rptr += tw->tw_bytes_xfered;
	}

	uhci_remove_bulk_tds_tws(uhcip, tw->tw_pipe_private, UHCI_IN_ERROR);

	/*
	 * When there  are no pending bulk commands, point the end of the
	 * lattice tree to NULL. This will make sure that the  HC control
	 * does not loop anymore and PCI bus is not affected.
	 */
	if (--uhcip->uhci_pending_bulk_cmds == 0) {
		uhcip->uhci_bulk_xfers_q_tail->link_ptr = HC_END_OF_LIST;
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_handle_bulk_td_errors: count = %d",
		    uhcip->uhci_pending_bulk_cmds);
	}

	uhci_hcdi_callback(uhcip, pp, ph, tw, usb_err);
	uhci_deallocate_tw(uhcip, pp, tw);
}


/*
 * uhci_get_bulk_td_by_paddr:
 *	Obtain the address of the TD pool the physical address falls in.
 *
 * td_pool_pp - pointer to the address of the TD pool containing the paddr
 */
/* ARGSUSED */
static void
uhci_get_bulk_td_by_paddr(
	uhci_state_t			*uhcip,
	uhci_bulk_isoc_xfer_t		*info,
	uint32_t			paddr,
	uhci_bulk_isoc_td_pool_t	**td_pool_pp)
{
	uint_t				i = 0;

	while (i < info->num_pools) {
		*td_pool_pp = &info->td_pools[i];
		if (((*td_pool_pp)->cookie.dmac_address <= paddr) &&
		    (((*td_pool_pp)->cookie.dmac_address +
		    (*td_pool_pp)->cookie.dmac_size) > paddr)) {

			break;
		}
		i++;
	}

	ASSERT(i < info->num_pools);
}


void
uhci_remove_bulk_tds_tws(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	int			what)
{
	uint_t			rval, i;
	uhci_td_t		*head;
	uhci_td_t		*head_next;
	usb_opaque_t		curr_reqp;
	uhci_bulk_isoc_xfer_t	*info;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	if ((info = pp->pp_qh->bulk_xfer_info) == NULL) {

		return;
	}

	head = uhcip->uhci_outst_tds_head;

	while (head) {
		uhci_trans_wrapper_t *tw_tmp = head->tw;
		head_next = head->outst_td_next;

		if (pp->pp_qh == tw_tmp->tw_pipe_private->pp_qh) {
			curr_reqp = tw_tmp->tw_curr_xfer_reqp;
			if (curr_reqp &&
			    ((what == UHCI_IN_CLOSE) ||
			    (what == UHCI_IN_RESET))) {
				uhci_hcdi_callback(uhcip, pp,
				    pp->pp_pipe_handle,
				    tw_tmp, USB_CR_FLUSHED);
			} /* end of curr_reqp */

			uhci_delete_td(uhcip, head);

			if (what == UHCI_IN_CLOSE || what == UHCI_IN_RESET) {
				ASSERT(info->num_tds > 0);
				if (--info->num_tds == 0) {
					uhci_deallocate_tw(uhcip, pp, tw_tmp);

					/*
					 * This will make sure that the HC
					 * does not loop anymore when there
					 * are no pending bulk commands.
					 */
					if (--uhcip->uhci_pending_bulk_cmds
					    == 0) {
						uhcip->uhci_bulk_xfers_q_tail->
						    link_ptr = HC_END_OF_LIST;
						USB_DPRINTF_L3(PRINT_MASK_ATTA,
						    uhcip->uhci_log_hdl,
						    "uhci_remove_bulk_tds_tws:"
						    " count = %d",
						    uhcip->
						    uhci_pending_bulk_cmds);
					}
				}
			}
		}

		head = head_next;
	}

	if (what == UHCI_IN_CLOSE || what == UHCI_IN_RESET) {
		ASSERT(info->num_tds == 0);
	}

	for (i = 0; i < info->num_pools; i++) {
		td_pool_ptr = &info->td_pools[i];
		rval = ddi_dma_unbind_handle(td_pool_ptr->dma_handle);
		ASSERT(rval == DDI_SUCCESS);
		ddi_dma_mem_free(&td_pool_ptr->mem_handle);
		ddi_dma_free_handle(&td_pool_ptr->dma_handle);
	}
	kmem_free(info->td_pools, (sizeof (uhci_bulk_isoc_td_pool_t) *
	    info->num_pools));
	kmem_free(info, sizeof (uhci_bulk_isoc_xfer_t));
	pp->pp_qh->bulk_xfer_info = NULL;
}


/*
 * uhci_save_data_toggle ()
 *	Save the data toggle in the usba_device structure
 */
void
uhci_save_data_toggle(uhci_pipe_private_t *pp)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	/* Save the data toggle in the usb devices structure. */
	mutex_enter(&ph->p_mutex);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    pp->pp_data_toggle);
	mutex_exit(&ph->p_mutex);
}

/*
 * uhci_create_isoc_transfer_wrapper:
 *	Create a Transaction Wrapper (TW) for isoc transfer.
 *	This involves the allocating of DMA resources.
 *
 *	For isoc transfers, one isoc transfer includes multiple packets
 *	and each packet may have a different length. So each packet is
 *	transfered by one TD. We only know the individual packet length
 *	won't exceed 1023 bytes, but we don't know exactly the lengths.
 *	It is hard to make one physically discontiguous DMA buffer which
 *	can fit in all the TDs like what can be done to the ctrl/bulk/
 *	intr transfers. It is also undesirable to make one physically
 *	contiguous DMA buffer for all the packets, since this may easily
 *	fail when the system is in low memory. So an individual DMA
 *	buffer is allocated for an individual isoc packet and each DMA
 *	buffer is physically contiguous. An extra structure is allocated
 *	to save the multiple DMA handles.
 */
static uhci_trans_wrapper_t *
uhci_create_isoc_transfer_wrapper(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	usb_isoc_req_t		*req,
	size_t			length,
	usb_flags_t		usb_flags)
{
	int			result;
	size_t			real_length, strtlen, xfer_size;
	uhci_trans_wrapper_t	*tw;
	ddi_device_acc_attr_t	dev_attr;
	ddi_dma_attr_t		dma_attr;
	int			kmem_flag;
	int			(*dmamem_wait)(caddr_t);
	uint_t			i, j, ccount;
	usb_isoc_req_t		*tmp_req = req;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	if (UHCI_XFER_TYPE(&pp->pp_pipe_handle->p_ep) != USB_EP_ATTR_ISOCH) {

		return (NULL);
	}

	if ((req == NULL) && (UHCI_XFER_DIR(&pp->pp_pipe_handle->p_ep) ==
	    USB_EP_DIR_IN)) {
		tmp_req = (usb_isoc_req_t *)pp->pp_client_periodic_in_reqp;
	}

	if (tmp_req == NULL) {

		return (NULL);
	}


	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_create_isoc_transfer_wrapper: length = 0x%lx flags = 0x%x",
	    length, usb_flags);

	/* SLEEP flag should not be used in interrupt context */
	if (servicing_interrupt()) {
		kmem_flag = KM_NOSLEEP;
		dmamem_wait = DDI_DMA_DONTWAIT;
	} else {
		kmem_flag = KM_SLEEP;
		dmamem_wait = DDI_DMA_SLEEP;
	}

	/* Allocate space for the transfer wrapper */
	if ((tw = kmem_zalloc(sizeof (uhci_trans_wrapper_t), kmem_flag)) ==
	    NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS,  uhcip->uhci_log_hdl,
		    "uhci_create_isoc_transfer_wrapper: kmem_alloc failed");

		return (NULL);
	}

	/* Allocate space for the isoc buffer handles */
	strtlen = sizeof (uhci_isoc_buf_t) * tmp_req->isoc_pkts_count;
	if ((tw->tw_isoc_bufs = kmem_zalloc(strtlen, kmem_flag)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS,  uhcip->uhci_log_hdl,
		    "uhci_create_isoc_transfer_wrapper: kmem_alloc "
		    "isoc buffer failed");
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	bcopy(&uhcip->uhci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = 1;

	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* Store the transfer length */
	tw->tw_length = length;

	for (i = 0; i < tmp_req->isoc_pkts_count; i++) {
		tw->tw_isoc_bufs[i].index = (ushort_t)i;

		/* Allocate the DMA handle */
		if ((result = ddi_dma_alloc_handle(uhcip->uhci_dip, &dma_attr,
		    dmamem_wait, 0, &tw->tw_isoc_bufs[i].dma_handle)) !=
		    DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_create_isoc_transfer_wrapper: "
			    "Alloc handle %d failed", i);

			for (j = 0; j < i; j++) {
				result = ddi_dma_unbind_handle(
				    tw->tw_isoc_bufs[j].dma_handle);
				ASSERT(result == USB_SUCCESS);
				ddi_dma_mem_free(&tw->tw_isoc_bufs[j].
				    mem_handle);
				ddi_dma_free_handle(&tw->tw_isoc_bufs[j].
				    dma_handle);
			}
			kmem_free(tw->tw_isoc_bufs, strtlen);
			kmem_free(tw, sizeof (uhci_trans_wrapper_t));

			return (NULL);
		}

		/* Allocate the memory */
		xfer_size = tmp_req->isoc_pkt_descr[i].isoc_pkt_length;
		if ((result = ddi_dma_mem_alloc(tw->tw_isoc_bufs[i].dma_handle,
		    xfer_size, &dev_attr, DDI_DMA_CONSISTENT, dmamem_wait,
		    NULL, (caddr_t *)&tw->tw_isoc_bufs[i].buf_addr,
		    &real_length, &tw->tw_isoc_bufs[i].mem_handle)) !=
		    DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_create_isoc_transfer_wrapper: "
			    "dma_mem_alloc %d fail", i);
			ddi_dma_free_handle(&tw->tw_isoc_bufs[i].dma_handle);

			for (j = 0; j < i; j++) {
				result = ddi_dma_unbind_handle(
				    tw->tw_isoc_bufs[j].dma_handle);
				ASSERT(result == USB_SUCCESS);
				ddi_dma_mem_free(&tw->tw_isoc_bufs[j].
				    mem_handle);
				ddi_dma_free_handle(&tw->tw_isoc_bufs[j].
				    dma_handle);
			}
			kmem_free(tw->tw_isoc_bufs, strtlen);
			kmem_free(tw, sizeof (uhci_trans_wrapper_t));

			return (NULL);
		}

		ASSERT(real_length >= xfer_size);

		/* Bind the handle */
		result = ddi_dma_addr_bind_handle(
		    tw->tw_isoc_bufs[i].dma_handle, NULL,
		    (caddr_t)tw->tw_isoc_bufs[i].buf_addr, real_length,
		    DDI_DMA_RDWR|DDI_DMA_CONSISTENT, dmamem_wait, NULL,
		    &tw->tw_isoc_bufs[i].cookie, &ccount);

		if ((result == DDI_DMA_MAPPED) && (ccount == 1)) {
			tw->tw_isoc_bufs[i].length = xfer_size;

			continue;
		} else {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_create_isoc_transfer_wrapper: "
			    "Bind handle %d failed", i);
			if (result == DDI_DMA_MAPPED) {
				result = ddi_dma_unbind_handle(
				    tw->tw_isoc_bufs[i].dma_handle);
				ASSERT(result == USB_SUCCESS);
			}
			ddi_dma_mem_free(&tw->tw_isoc_bufs[i].mem_handle);
			ddi_dma_free_handle(&tw->tw_isoc_bufs[i].dma_handle);

			for (j = 0; j < i; j++) {
				result = ddi_dma_unbind_handle(
				    tw->tw_isoc_bufs[j].dma_handle);
				ASSERT(result == USB_SUCCESS);
				ddi_dma_mem_free(&tw->tw_isoc_bufs[j].
				    mem_handle);
				ddi_dma_free_handle(&tw->tw_isoc_bufs[j].
				    dma_handle);
			}
			kmem_free(tw->tw_isoc_bufs, strtlen);
			kmem_free(tw, sizeof (uhci_trans_wrapper_t));

			return (NULL);
		}
	}

	tw->tw_ncookies = tmp_req->isoc_pkts_count;
	tw->tw_isoc_strtlen = strtlen;

	/*
	 * Only allow one wrapper to be added at a time. Insert the
	 * new transaction wrapper into the list for this pipe.
	 */
	if (pp->pp_tw_head == NULL) {
		pp->pp_tw_head = tw;
		pp->pp_tw_tail = tw;
	} else {
		pp->pp_tw_tail->tw_next = tw;
		pp->pp_tw_tail = tw;
		ASSERT(tw->tw_next == NULL);
	}

	/* Store a back pointer to the pipe private structure */
	tw->tw_pipe_private = pp;

	/* Store the transfer type - synchronous or asynchronous */
	tw->tw_flags = usb_flags;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_create_isoc_transfer_wrapper: tw = 0x%p, ncookies = %u",
	    (void *)tw, tw->tw_ncookies);

	return (tw);
}

/*
 * uhci_insert_isoc_td:
 *	- Create transfer wrapper
 *	- Allocate memory for the isoc td's
 *	- Fill up all the TD's and submit to the HC
 *	- Update all the linked lists
 */
int
uhci_insert_isoc_td(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_req,
	size_t			length,
	usb_flags_t		flags)
{
	int			rval = USB_SUCCESS;
	int			error;
	uint_t			ddic;
	uint32_t		i, j, index;
	uint32_t		bytes_to_xfer;
	uint32_t		expired_frames = 0;
	usb_frame_number_t	start_frame, end_frame, current_frame;
	uhci_td_t		*td_ptr;
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	uhci_trans_wrapper_t	*tw;
	uhci_bulk_isoc_xfer_t	*isoc_xfer_info;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr;

	USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_insert_isoc_td: ph = 0x%p isoc req = %p length = %lu",
	    (void *)ph, (void *)isoc_req, length);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Allocate a transfer wrapper */
	if ((tw = uhci_create_isoc_transfer_wrapper(uhcip, pp, isoc_req,
	    length, flags)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_insert_isoc_td: TW allocation failed");

		return (USB_NO_RESOURCES);
	}

	/* Save current isochronous request pointer */
	tw->tw_curr_xfer_reqp = (usb_opaque_t)isoc_req;

	/*
	 * Initialize the transfer wrapper. These values are useful
	 * for sending back the reply.
	 */
	tw->tw_handle_td		= uhci_handle_isoc_td;
	tw->tw_handle_callback_value	= NULL;
	tw->tw_direction = (UHCI_XFER_DIR(&ph->p_ep) == USB_EP_DIR_OUT) ?
	    PID_OUT : PID_IN;

	/*
	 * If the transfer isoc send, then copy the data from the request
	 * to the transfer wrapper.
	 */
	if ((tw->tw_direction == PID_OUT) && length) {
		uchar_t *p;

		ASSERT(isoc_req->isoc_data != NULL);
		p = isoc_req->isoc_data->b_rptr;

		/* Copy the data into the message */
		for (i = 0; i < isoc_req->isoc_pkts_count; i++) {
			ddi_rep_put8(tw->tw_isoc_bufs[i].mem_handle,
			    p, (uint8_t *)tw->tw_isoc_bufs[i].buf_addr,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_length,
			    DDI_DEV_AUTOINCR);
			p += isoc_req->isoc_pkt_descr[i].isoc_pkt_length;
		}
	}

	if (tw->tw_direction == PID_IN) {
		if ((rval = uhci_allocate_periodic_in_resource(uhcip, pp, tw,
		    flags)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
			    "uhci_insert_isoc_td: isoc_req_t alloc failed");
			uhci_deallocate_tw(uhcip, pp, tw);

			return (rval);
		}

		isoc_req = (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;
	}

	tw->tw_isoc_req	= (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;

	/* Get the pointer to the isoc_xfer_info structure */
	isoc_xfer_info = (uhci_bulk_isoc_xfer_t *)&tw->tw_xfer_info;
	isoc_xfer_info->num_tds = isoc_req->isoc_pkts_count;

	/*
	 * Allocate memory for isoc tds
	 */
	if ((rval = uhci_alloc_bulk_isoc_tds(uhcip, isoc_req->isoc_pkts_count,
	    isoc_xfer_info)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_alloc_bulk_isoc_td: Memory allocation failure");

		if (tw->tw_direction == PID_IN) {
			uhci_deallocate_periodic_in_resource(uhcip, pp, tw);
		}
		uhci_deallocate_tw(uhcip, pp, tw);

		return (rval);
	}

	/*
	 * Get the isoc td pool address, buffer address and
	 * max packet size that the device supports.
	 */
	td_pool_ptr = &isoc_xfer_info->td_pools[0];
	td_ptr = (uhci_td_t *)td_pool_ptr->pool_addr;
	index = 0;

	/*
	 * Fill up the isoc tds
	 */
	USB_DPRINTF_L3(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_insert_isoc_td : isoc pkts %d", isoc_req->isoc_pkts_count);

	for (i = 0; i < isoc_xfer_info->num_pools; i++) {
		for (j = 0; j < td_pool_ptr->num_tds; j++) {
			bytes_to_xfer =
			    isoc_req->isoc_pkt_descr[index].isoc_pkt_length;

			uhci_fill_in_bulk_isoc_td(uhcip, &td_ptr[j],
			    (uhci_td_t *)NULL, HC_END_OF_LIST, ph, index,
			    bytes_to_xfer, tw);
			td_ptr[j].isoc_pkt_index = (ushort_t)index;
			index++;
		}

		if (i < (isoc_xfer_info->num_pools - 1)) {
			td_pool_ptr = &isoc_xfer_info->td_pools[i + 1];
			td_ptr = (uhci_td_t *)td_pool_ptr->pool_addr;
		}
	}

	/*
	 * Get the starting frame number.
	 * The client drivers sets the flag USB_ATTRS_ISOC_XFER_ASAP to inform
	 * the HCD to care of starting frame number.
	 *
	 * Following code is very time critical. So, perform atomic execution.
	 */
	ddic = ddi_enter_critical();
	current_frame = uhci_get_sw_frame_number(uhcip);

	if (isoc_req->isoc_attributes & USB_ATTRS_ISOC_START_FRAME) {
		start_frame = isoc_req->isoc_frame_no;
		end_frame = start_frame + isoc_req->isoc_pkts_count;

		/* Check available frames */
		if ((end_frame - current_frame) < UHCI_MAX_ISOC_FRAMES) {
			if (current_frame > start_frame) {
				if ((current_frame + FRNUM_OFFSET) <
				    end_frame) {
					expired_frames = current_frame +
					    FRNUM_OFFSET - start_frame;
					start_frame = current_frame +
					    FRNUM_OFFSET;
				} else {
					rval = USB_INVALID_START_FRAME;
				}
			}
		} else {
			rval = USB_INVALID_START_FRAME;
		}

	} else if (isoc_req->isoc_attributes & USB_ATTRS_ISOC_XFER_ASAP) {
		start_frame = pp->pp_frame_num;

		if (start_frame == INVALID_FRNUM) {
			start_frame = current_frame + FRNUM_OFFSET;
		} else if (current_frame > start_frame) {
			start_frame = current_frame + FRNUM_OFFSET;
		}

		end_frame = start_frame + isoc_req->isoc_pkts_count;
		isoc_req->isoc_frame_no = start_frame;

	}

	if (rval != USB_SUCCESS) {

		/* Exit the critical */
		ddi_exit_critical(ddic);

		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_insert_isoc_td: Invalid starting frame number");

		if (tw->tw_direction == PID_IN) {
			uhci_deallocate_periodic_in_resource(uhcip, pp, tw);
		}

		while (tw->tw_hctd_head) {
			uhci_delete_td(uhcip, tw->tw_hctd_head);
		}

		for (i = 0; i < isoc_xfer_info->num_pools; i++) {
			td_pool_ptr = &isoc_xfer_info->td_pools[i];
			error = ddi_dma_unbind_handle(td_pool_ptr->dma_handle);
			ASSERT(error == DDI_SUCCESS);
			ddi_dma_mem_free(&td_pool_ptr->mem_handle);
			ddi_dma_free_handle(&td_pool_ptr->dma_handle);
		}
		kmem_free(isoc_xfer_info->td_pools,
		    (sizeof (uhci_bulk_isoc_td_pool_t) *
		    isoc_xfer_info->num_pools));

		uhci_deallocate_tw(uhcip, pp, tw);

		return (rval);
	}

	for (i = 0; i < expired_frames; i++) {
		isoc_req->isoc_pkt_descr[i].isoc_pkt_status =
		    USB_CR_NOT_ACCESSED;
		isoc_req->isoc_pkt_descr[i].isoc_pkt_actual_length =
		    isoc_req->isoc_pkt_descr[i].isoc_pkt_length;
		uhci_get_isoc_td_by_index(uhcip, isoc_xfer_info, i,
		    &td_ptr, &td_pool_ptr);
		uhci_delete_td(uhcip, td_ptr);
		--isoc_xfer_info->num_tds;
	}

	/*
	 * Add the TD's to the HC list
	 */
	start_frame = (start_frame & 0x3ff);
	for (; i < isoc_req->isoc_pkts_count; i++) {
		uhci_get_isoc_td_by_index(uhcip, isoc_xfer_info, i,
		    &td_ptr, &td_pool_ptr);
		if (uhcip->uhci_isoc_q_tailp[start_frame]) {
			td_ptr->isoc_prev =
			    uhcip->uhci_isoc_q_tailp[start_frame];
			td_ptr->isoc_next = NULL;
			td_ptr->link_ptr =
			    uhcip->uhci_isoc_q_tailp[start_frame]->link_ptr;
			uhcip->uhci_isoc_q_tailp[start_frame]->isoc_next =
			    td_ptr;
			SetTD32(uhcip,
			    uhcip->uhci_isoc_q_tailp[start_frame]->link_ptr,
			    ISOCTD_PADDR(td_pool_ptr, td_ptr));
			uhcip->uhci_isoc_q_tailp[start_frame] = td_ptr;
		} else {
			uhcip->uhci_isoc_q_tailp[start_frame] = td_ptr;
			td_ptr->isoc_next = NULL;
			td_ptr->isoc_prev = NULL;
			SetTD32(uhcip, td_ptr->link_ptr,
			    GetFL32(uhcip,
			    uhcip->uhci_frame_lst_tablep[start_frame]));
			SetFL32(uhcip,
			    uhcip->uhci_frame_lst_tablep[start_frame],
			    ISOCTD_PADDR(td_pool_ptr, td_ptr));
		}
		td_ptr->starting_frame = (uint_t)start_frame;

		if (++start_frame == NUM_FRAME_LST_ENTRIES)
			start_frame = 0;
	}

	ddi_exit_critical(ddic);
	pp->pp_frame_num = end_frame;

	USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_insert_isoc_td: current frame number 0x%llx, pipe frame num"
	    " 0x%llx", (unsigned long long)current_frame,
	    (unsigned long long)(pp->pp_frame_num));

	return (rval);
}


/*
 * uhci_get_isoc_td_by_index:
 *	Obtain the addresses of the TD pool and the TD at the index.
 *
 * tdpp - pointer to the address of the TD at the isoc packet index
 * td_pool_pp - pointer to the address of the TD pool containing
 *		the specified TD
 */
/* ARGSUSED */
static void
uhci_get_isoc_td_by_index(
	uhci_state_t			*uhcip,
	uhci_bulk_isoc_xfer_t		*info,
	uint_t				index,
	uhci_td_t			**tdpp,
	uhci_bulk_isoc_td_pool_t	**td_pool_pp)
{
	uint_t			i = 0, j = 0;
	uhci_td_t		*td_ptr;

	while (j < info->num_pools) {
		if ((i + info->td_pools[j].num_tds) <= index) {
			i += info->td_pools[j].num_tds;
			j++;
		} else {
			i = index - i;

			break;
		}
	}

	ASSERT(j < info->num_pools);
	*td_pool_pp = &info->td_pools[j];
	td_ptr = (uhci_td_t *)((*td_pool_pp)->pool_addr);
	*tdpp = &td_ptr[i];
}


/*
 * uhci_handle_isoc_td:
 *	Handles the completed isoc tds
 */
void
uhci_handle_isoc_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	uint_t			rval, i;
	uint32_t		pkt_index = td->isoc_pkt_index;
	usb_cr_t		cr;
	uhci_trans_wrapper_t	*tw = td->tw;
	usb_isoc_req_t		*isoc_req = (usb_isoc_req_t *)tw->tw_isoc_req;
	uhci_pipe_private_t	*pp = tw->tw_pipe_private;
	uhci_bulk_isoc_xfer_t	*isoc_xfer_info = &tw->tw_xfer_info;
	usba_pipe_handle_data_t	*usb_pp;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr;

	USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_handle_isoc_td: td = 0x%p, pp = 0x%p, tw = 0x%p, req = 0x%p, "
	    "index = %x", (void *)td, (void *)pp, (void *)tw, (void *)isoc_req,
	    pkt_index);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	usb_pp = pp->pp_pipe_handle;

	/*
	 * Check whether there are any errors occurred. If so, update error
	 * count and return it to the upper.But never return a non zero
	 * completion reason.
	 */
	cr = USB_CR_OK;
	if (GetTD_status(uhcip, td) & TD_STATUS_MASK) {
		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_handle_isoc_td: Error Occurred: TD Status = %x",
		    GetTD_status(uhcip, td));
		isoc_req->isoc_error_count++;
	}

	if (isoc_req != NULL) {
		isoc_req->isoc_pkt_descr[pkt_index].isoc_pkt_status = cr;
		isoc_req->isoc_pkt_descr[pkt_index].isoc_pkt_actual_length =
		    (GetTD_alen(uhcip, td) == ZERO_LENGTH) ? 0 :
		    GetTD_alen(uhcip, td) + 1;
	}

	uhci_delete_isoc_td(uhcip, td);

	if (--isoc_xfer_info->num_tds != 0) {
		USB_DPRINTF_L3(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_handle_isoc_td: Number of TDs %d",
		    isoc_xfer_info->num_tds);

		return;
	}

	tw->tw_claim = UHCI_INTR_HDLR_CLAIMED;
	if (tw->tw_direction == PID_IN) {
		uhci_sendup_td_message(uhcip, cr, tw);

		if ((uhci_handle_isoc_receive(uhcip, pp, tw)) != USB_SUCCESS) {
			USB_DPRINTF_L3(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
			    "uhci_handle_isoc_td: Drop message");
		}

	} else {
		/* update kstats only for OUT. sendup_td_msg() does it for IN */
		uhci_do_byte_stats(uhcip, tw->tw_length,
		    usb_pp->p_ep.bmAttributes, usb_pp->p_ep.bEndpointAddress);

		uhci_hcdi_callback(uhcip, pp, usb_pp, tw, USB_CR_OK);
	}

	for (i = 0; i < isoc_xfer_info->num_pools; i++) {
		td_pool_ptr = &isoc_xfer_info->td_pools[i];
		rval = ddi_dma_unbind_handle(td_pool_ptr->dma_handle);
		ASSERT(rval == DDI_SUCCESS);
		ddi_dma_mem_free(&td_pool_ptr->mem_handle);
		ddi_dma_free_handle(&td_pool_ptr->dma_handle);
	}
	kmem_free(isoc_xfer_info->td_pools,
	    (sizeof (uhci_bulk_isoc_td_pool_t) *
	    isoc_xfer_info->num_pools));
	uhci_deallocate_tw(uhcip, pp, tw);
}


/*
 * uhci_handle_isoc_receive:
 *	- Sends the isoc data to the client
 *	- Inserts another isoc receive request
 */
static int
uhci_handle_isoc_receive(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	uhci_trans_wrapper_t	*tw)
{
	USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_handle_isoc_receive: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * -- check for pipe state being polling before
	 * inserting a new request. Check when is TD
	 * de-allocation being done? (so we can reuse the same TD)
	 */
	if (uhci_start_isoc_receive_polling(uhcip,
	    pp->pp_pipe_handle, (usb_isoc_req_t *)tw->tw_curr_xfer_reqp,
	    0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_handle_isoc_receive: receive polling failed");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * uhci_delete_isoc_td:
 *	- Delete from the outstanding command queue
 *	- Delete from the tw queue
 *	- Delete from the isoc queue
 *	- Delete from the HOST CONTROLLER list
 */
static void
uhci_delete_isoc_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	uint32_t	starting_frame = td->starting_frame;

	if ((td->isoc_next == NULL) && (td->isoc_prev == NULL)) {
		SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[starting_frame],
		    GetTD32(uhcip, td->link_ptr));
		uhcip->uhci_isoc_q_tailp[starting_frame] = 0;
	} else if (td->isoc_next == NULL) {
		td->isoc_prev->link_ptr = td->link_ptr;
		td->isoc_prev->isoc_next = NULL;
		uhcip->uhci_isoc_q_tailp[starting_frame] = td->isoc_prev;
	} else if (td->isoc_prev == NULL) {
		td->isoc_next->isoc_prev = NULL;
		SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[starting_frame],
		    GetTD32(uhcip, td->link_ptr));
	} else {
		td->isoc_prev->isoc_next = td->isoc_next;
		td->isoc_next->isoc_prev = td->isoc_prev;
		td->isoc_prev->link_ptr = td->link_ptr;
	}

	uhci_delete_td(uhcip, td);
}


/*
 * uhci_send_isoc_receive
 *	- Allocates usb_isoc_request
 *	- Updates the isoc request
 *	- Inserts the isoc td's into the HC processing list.
 */
int
uhci_start_isoc_receive_polling(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_req,
	usb_flags_t		usb_flags)
{
	int			ii, error;
	size_t			max_isoc_xfer_size, length, isoc_pkts_length;
	ushort_t		isoc_pkt_count;
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	usb_isoc_pkt_descr_t	*isoc_pkt_descr;

	USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_start_isoc_receive_polling: usb_flags = %x", usb_flags);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	max_isoc_xfer_size = ph->p_ep.wMaxPacketSize * UHCI_MAX_ISOC_PKTS;

	if (isoc_req) {
		isoc_pkt_descr = isoc_req->isoc_pkt_descr;
		isoc_pkt_count = isoc_req->isoc_pkts_count;
		isoc_pkts_length = isoc_req->isoc_pkts_length;
	} else {
		isoc_pkt_descr = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkt_descr;
		isoc_pkt_count = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkts_count;
		isoc_pkts_length = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkts_length;
	}

	for (ii = 0, length = 0; ii < isoc_pkt_count; ii++) {
		length += isoc_pkt_descr->isoc_pkt_length;
		isoc_pkt_descr++;
	}

	if ((isoc_pkts_length) && (isoc_pkts_length != length)) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_start_isoc_receive_polling: isoc_pkts_length 0x%lx "
		    "is not equal to the sum of all pkt lengths 0x%lx in "
		    "an isoc request", isoc_pkts_length, length);

		return (USB_FAILURE);
	}

	/* Check the size of isochronous request */
	if (length > max_isoc_xfer_size) {
		USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_start_isoc_receive_polling: "
		    "Max isoc request size = %lx, Given isoc req size = %lx",
		    max_isoc_xfer_size, length);

		return (USB_FAILURE);
	}

	/* Add the TD into the Host Controller's isoc list */
	error = uhci_insert_isoc_td(uhcip, ph, isoc_req, length, usb_flags);

	return (error);
}


/*
 * uhci_remove_isoc_tds_tws
 *	This routine scans the pipe and removes all the td's
 *	and transfer wrappers and deallocates the memory
 *	associated with those td's and tw's.
 */
void
uhci_remove_isoc_tds_tws(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	uint_t			rval, i;
	uhci_td_t		*tmp_td, *td_head;
	usb_isoc_req_t		*isoc_req;
	uhci_trans_wrapper_t	*tmp_tw, *tw_head;
	uhci_bulk_isoc_xfer_t	*isoc_xfer_info;
	uhci_bulk_isoc_td_pool_t *td_pool_ptr;

	USB_DPRINTF_L4(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
	    "uhci_remove_isoc_tds_tws: pp = %p", (void *)pp);

	tw_head = pp->pp_tw_head;
	while (tw_head) {
		tmp_tw = tw_head;
		tw_head = tw_head->tw_next;
		td_head = tmp_tw->tw_hctd_head;
		if (tmp_tw->tw_direction == PID_IN) {
			uhci_deallocate_periodic_in_resource(uhcip, pp,
			    tmp_tw);
		} else if (tmp_tw->tw_direction == PID_OUT) {
			uhci_hcdi_callback(uhcip, pp, pp->pp_pipe_handle,
			    tmp_tw, USB_CR_FLUSHED);
		}

		while (td_head) {
			tmp_td = td_head;
			td_head = td_head->tw_td_next;
			uhci_delete_isoc_td(uhcip, tmp_td);
		}

		isoc_req = (usb_isoc_req_t *)tmp_tw->tw_isoc_req;
		if (isoc_req) {
			usb_free_isoc_req(isoc_req);
		}

		ASSERT(tmp_tw->tw_hctd_head == NULL);

		if (tmp_tw->tw_xfer_info.td_pools) {
			isoc_xfer_info =
			    (uhci_bulk_isoc_xfer_t *)&tmp_tw->tw_xfer_info;
			for (i = 0; i < isoc_xfer_info->num_pools; i++) {
				td_pool_ptr = &isoc_xfer_info->td_pools[i];
				rval = ddi_dma_unbind_handle(
				    td_pool_ptr->dma_handle);
				ASSERT(rval == DDI_SUCCESS);
				ddi_dma_mem_free(&td_pool_ptr->mem_handle);
				ddi_dma_free_handle(&td_pool_ptr->dma_handle);
			}
			kmem_free(isoc_xfer_info->td_pools,
			    (sizeof (uhci_bulk_isoc_td_pool_t) *
			    isoc_xfer_info->num_pools));
		}

		uhci_deallocate_tw(uhcip, pp, tmp_tw);
	}
}


/*
 * uhci_isoc_update_sw_frame_number()
 *	to avoid code duplication, call uhci_get_sw_frame_number()
 */
void
uhci_isoc_update_sw_frame_number(uhci_state_t *uhcip)
{
	(void) uhci_get_sw_frame_number(uhcip);
}


/*
 * uhci_get_sw_frame_number:
 *	Hold the uhci_int_mutex before calling this routine.
 */
uint64_t
uhci_get_sw_frame_number(uhci_state_t *uhcip)
{
	uint64_t sw_frnum, hw_frnum, current_frnum;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	sw_frnum = uhcip->uhci_sw_frnum;
	hw_frnum = Get_OpReg16(FRNUM);

	/*
	 * Check bit 10 in the software counter and hardware frame counter.
	 * If both are same, then don't increment the software frame counter
	 * (Bit 10 of hw frame counter toggle for every 1024 frames)
	 * The lower 11 bits of software counter contains the hardware frame
	 * counter value. The MSB (bit 10) of software counter is incremented
	 * for every 1024 frames either here or in get frame number routine.
	 */
	if ((sw_frnum & UHCI_BIT_10_MASK) == (hw_frnum & UHCI_BIT_10_MASK)) {
		/* The MSB of hw counter did not toggle */
		current_frnum = ((sw_frnum & (SW_FRNUM_MASK)) | hw_frnum);
	} else {
		/*
		 * The hw counter wrapped around. And the interrupt handler
		 * did not get a chance to update the sw frame counter.
		 * So, update the sw frame counter and return correct frame no.
		 */
		sw_frnum >>= UHCI_SIZE_OF_HW_FRNUM - 1;
		current_frnum =
		    ((++sw_frnum << (UHCI_SIZE_OF_HW_FRNUM - 1)) | hw_frnum);
	}
	uhcip->uhci_sw_frnum = current_frnum;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_get_sw_frame_number: sw=%lld hd=%lld",
	    (unsigned long long)(uhcip->uhci_sw_frnum),
	    (unsigned long long)hw_frnum);

	return (current_frnum);
}


/*
 * uhci_cmd_timeout_hdlr:
 *	This routine will get called for every second. It checks for
 *	timed out control commands/bulk commands. Timeout any commands
 *	that exceeds the time out period specified by the pipe policy.
 */
void
uhci_cmd_timeout_hdlr(void *arg)
{
	uint_t			flag = B_FALSE;
	uhci_td_t		*head, *tmp_td;
	uhci_state_t		*uhcip = (uhci_state_t *)arg;
	uhci_pipe_private_t	*pp;

	/*
	 * Check whether any of the control xfers are timed out.
	 * If so, complete those commands with time out as reason.
	 */
	mutex_enter(&uhcip->uhci_int_mutex);
	head = uhcip->uhci_outst_tds_head;

	while (head) {
		/*
		 * If timeout out is zero, then dont timeout command.
		 */
		if (head->tw->tw_timeout_cnt == 0)  {
			head = head->outst_td_next;
			continue;
		}

		if (!(head->tw->tw_flags & TW_TIMEOUT_FLAG)) {
			head->tw->tw_flags |= TW_TIMEOUT_FLAG;
			--head->tw->tw_timeout_cnt;
		}

		/* only do it for bulk and control TDs */
		if ((head->tw->tw_timeout_cnt == 0) &&
		    (head->tw->tw_handle_td != uhci_handle_isoc_td)) {

			USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "Command timed out: td = %p", (void *)head);

			head->tw->tw_claim = UHCI_TIMEOUT_HDLR_CLAIMED;

			/*
			 * Check finally whether the command completed
			 */
			if (GetTD_status(uhcip, head) & UHCI_TD_ACTIVE) {
				SetTD32(uhcip, head->link_ptr,
				    GetTD32(uhcip, head->link_ptr) |
				    HC_END_OF_LIST);
				pp = head->tw->tw_pipe_private;
				SetQH32(uhcip, pp->pp_qh->element_ptr,
				    GetQH32(uhcip, pp->pp_qh->element_ptr) |
				    HC_END_OF_LIST);
			}

			flag = B_TRUE;
		}

		head = head->outst_td_next;
	}

	if (flag) {
		(void) uhci_wait_for_sof(uhcip);
	}

	head = uhcip->uhci_outst_tds_head;
	while (head) {
		if (head->tw->tw_flags & TW_TIMEOUT_FLAG) {
			head->tw->tw_flags &= ~TW_TIMEOUT_FLAG;
		}
		if (head->tw->tw_claim == UHCI_TIMEOUT_HDLR_CLAIMED) {
			head->tw->tw_claim = UHCI_NOT_CLAIMED;
			tmp_td = head->tw->tw_hctd_head;
			while (tmp_td) {
				SetTD_status(uhcip, tmp_td,
				    UHCI_TD_CRC_TIMEOUT);
				tmp_td = tmp_td->tw_td_next;
			}
		}
		head = head->outst_td_next;
	}

	/*
	 * Process the td which was completed before shifting from normal
	 * mode to polled mode
	 */
	if (uhcip->uhci_polled_flag == UHCI_POLLED_FLAG_TRUE) {
		uhci_process_submitted_td_queue(uhcip);
		uhcip->uhci_polled_flag = UHCI_POLLED_FLAG_FALSE;
	} else if (flag) {
		/* Process the completed/timed out commands */
		uhci_process_submitted_td_queue(uhcip);
	}

	/* Re-register the control/bulk/intr commands' timeout handler */
	if (uhcip->uhci_cmd_timeout_id) {
		uhcip->uhci_cmd_timeout_id = timeout(uhci_cmd_timeout_hdlr,
		    (void *)uhcip, UHCI_ONE_SECOND);
	}

	mutex_exit(&uhcip->uhci_int_mutex);
}


/*
 * uhci_wait_for_sof:
 *	Wait for the start of the next frame (implying any changes made in the
 *	lattice have now taken effect).
 *	To be sure this is the case, we wait for the completion of the current
 *	frame (which might have already been pending), then another complete
 *	frame to ensure everything has taken effect.
 */
int
uhci_wait_for_sof(uhci_state_t *uhcip)
{
	int	n, error;
	ushort_t    cmd_reg;
	usb_frame_number_t	before_frame_number, after_frame_number;
	clock_t	time, rval;
	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_wait_for_sof: uhcip = %p", (void *)uhcip);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	error = uhci_state_is_operational(uhcip);

	if (error != USB_SUCCESS) {

		return (error);
	}

	before_frame_number =  uhci_get_sw_frame_number(uhcip);
	for (n = 0; n < MAX_SOF_WAIT_COUNT; n++) {
		SetTD_ioc(uhcip, uhcip->uhci_sof_td, 1);
		uhcip->uhci_cv_signal = B_TRUE;

		time = ddi_get_lbolt() + UHCI_ONE_SECOND;
		rval = cv_timedwait(&uhcip->uhci_cv_SOF,
		    &uhcip->uhci_int_mutex, time);

		after_frame_number = uhci_get_sw_frame_number(uhcip);
		if ((rval == -1) &&
		    (after_frame_number <= before_frame_number)) {
			cmd_reg = Get_OpReg16(USBCMD);
			Set_OpReg16(USBCMD, (cmd_reg | USBCMD_REG_HC_RUN));
			Set_OpReg16(USBINTR, ENABLE_ALL_INTRS);
			after_frame_number = uhci_get_sw_frame_number(uhcip);
		}
		before_frame_number = after_frame_number;
	}

	SetTD_ioc(uhcip, uhcip->uhci_sof_td, 0);

	return (uhcip->uhci_cv_signal ? USB_FAILURE : USB_SUCCESS);

}

/*
 * uhci_allocate_periodic_in_resource:
 *	Allocate interrupt/isochronous request structure for the
 *	interrupt/isochronous IN transfer.
 */
int
uhci_allocate_periodic_in_resource(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	uhci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	size_t			length = 0;
	usb_opaque_t		client_periodic_in_reqp;
	usb_intr_req_t		*cur_intr_req;
	usb_isoc_req_t		*curr_isoc_reqp;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_allocate_periodic_in_resource:\n\t"
	    "ph = 0x%p, pp = 0x%p, tw = 0x%p, flags = 0x%x",
	    (void *)ph, (void *)pp, (void *)tw, flags);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Check the current periodic in request pointer */
	if (tw->tw_curr_xfer_reqp) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_allocate_periodic_in_resource: Interrupt "
		    "request structure already exists: "
		    "allocation failed");

		return (USB_SUCCESS);
	}

	/* Get the client periodic in request pointer */
	client_periodic_in_reqp = pp->pp_client_periodic_in_reqp;

	/*
	 * If it a periodic IN request and periodic request is NULL,
	 * allocate corresponding usb periodic IN request for the
	 * current periodic polling request and copy the information
	 * from the saved periodic request structure.
	 */
	if (UHCI_XFER_TYPE(&ph->p_ep) == USB_EP_ATTR_INTR) {
		/* Get the interrupt transfer length */
		length = ((usb_intr_req_t *)client_periodic_in_reqp)->
		    intr_len;

		cur_intr_req = usba_hcdi_dup_intr_req(ph->p_dip,
		    (usb_intr_req_t *)client_periodic_in_reqp, length, flags);
		if (cur_intr_req == NULL) {
			USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_allocate_periodic_in_resource: Interrupt "
			    "request structure allocation failed");

			return (USB_NO_RESOURCES);
		}

		/* Check and save the timeout value */
		tw->tw_timeout_cnt = (cur_intr_req->intr_attributes &
		    USB_ATTRS_ONE_XFER) ? cur_intr_req->intr_timeout: 0;
		tw->tw_curr_xfer_reqp = (usb_opaque_t)cur_intr_req;
		tw->tw_length = cur_intr_req->intr_len;
	} else {
		ASSERT(client_periodic_in_reqp != NULL);

		if ((curr_isoc_reqp = usba_hcdi_dup_isoc_req(ph->p_dip,
		    (usb_isoc_req_t *)client_periodic_in_reqp, flags)) ==
		    NULL) {
			USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_allocate_periodic_in_resource: Isochronous "
			    "request structure allocation failed");

			return (USB_NO_RESOURCES);
		}

		/*
		 * Save the client's isochronous request pointer and
		 * length of isochronous transfer in transfer wrapper.
		 * The dup'ed request is saved in pp_client_periodic_in_reqp
		 */
		tw->tw_curr_xfer_reqp =
		    (usb_opaque_t)pp->pp_client_periodic_in_reqp;
		pp->pp_client_periodic_in_reqp = (usb_opaque_t)curr_isoc_reqp;
	}

	mutex_enter(&ph->p_mutex);
	ph->p_req_count++;
	mutex_exit(&ph->p_mutex);

	return (USB_SUCCESS);
}


/*
 * uhci_deallocate_periodic_in_resource:
 *	Deallocate interrupt/isochronous request structure for the
 *	interrupt/isochronous IN transfer.
 */
void
uhci_deallocate_periodic_in_resource(
	uhci_state_t		*uhcip,
	uhci_pipe_private_t	*pp,
	uhci_trans_wrapper_t	*tw)
{
	usb_opaque_t		curr_xfer_reqp;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_deallocate_periodic_in_resource: "
	    "pp = 0x%p tw = 0x%p", (void *)pp, (void *)tw);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	curr_xfer_reqp = tw->tw_curr_xfer_reqp;
	if (curr_xfer_reqp) {
		/*
		 * Reset periodic in request usb isoch
		 * packet request pointers to null.
		 */
		tw->tw_curr_xfer_reqp = NULL;
		tw->tw_isoc_req = NULL;

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);

		/*
		 * Free pre-allocated interrupt or isochronous requests.
		 */
		switch (UHCI_XFER_TYPE(&ph->p_ep)) {
		case USB_EP_ATTR_INTR:
			usb_free_intr_req((usb_intr_req_t *)curr_xfer_reqp);
			break;
		case USB_EP_ATTR_ISOCH:
			usb_free_isoc_req((usb_isoc_req_t *)curr_xfer_reqp);
			break;
		}
	}
}


/*
 * uhci_hcdi_callback()
 *	convenience wrapper around usba_hcdi_callback()
 */
void
uhci_hcdi_callback(uhci_state_t *uhcip, uhci_pipe_private_t *pp,
    usba_pipe_handle_data_t *ph, uhci_trans_wrapper_t *tw, usb_cr_t cr)
{
	usb_opaque_t	curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_callback: ph = 0x%p, tw = 0x%p, cr = 0x%x",
	    (void *)ph, (void *)tw, cr);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	if (tw && tw->tw_curr_xfer_reqp) {
		curr_xfer_reqp = tw->tw_curr_xfer_reqp;
		tw->tw_curr_xfer_reqp = NULL;
		tw->tw_isoc_req = NULL;
	} else {
		ASSERT(pp->pp_client_periodic_in_reqp != NULL);

		curr_xfer_reqp = pp->pp_client_periodic_in_reqp;
		pp->pp_client_periodic_in_reqp = NULL;
	}

	ASSERT(curr_xfer_reqp != NULL);

	mutex_exit(&uhcip->uhci_int_mutex);
	usba_hcdi_cb(ph, curr_xfer_reqp, cr);
	mutex_enter(&uhcip->uhci_int_mutex);
}


/*
 * uhci_state_is_operational:
 *
 * Check the Host controller state and return proper values.
 */
int
uhci_state_is_operational(uhci_state_t	*uhcip)
{
	int	val;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	switch (uhcip->uhci_hc_soft_state) {
	case UHCI_CTLR_INIT_STATE:
	case UHCI_CTLR_SUSPEND_STATE:
		val = USB_FAILURE;
		break;
	case UHCI_CTLR_OPERATIONAL_STATE:
		val = USB_SUCCESS;
		break;
	case UHCI_CTLR_ERROR_STATE:
		val = USB_HC_HARDWARE_ERROR;
		break;
	default:
		val = USB_FAILURE;
		break;
	}

	return (val);
}


#ifdef DEBUG
static void
uhci_print_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	uint_t	*ptr = (uint_t *)td;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	USB_DPRINTF_L3(PRINT_MASK_DUMPING, uhcip->uhci_log_hdl,
	    "\tDWORD 1 0x%x\t DWORD 2 0x%x", ptr[0], ptr[1]);
	USB_DPRINTF_L3(PRINT_MASK_DUMPING, uhcip->uhci_log_hdl,
	    "\tDWORD 3 0x%x\t DWORD 4 0x%x", ptr[2], ptr[3]);
	USB_DPRINTF_L3(PRINT_MASK_DUMPING, uhcip->uhci_log_hdl,
	    "\tBytes xfered    = %d", td->tw->tw_bytes_xfered);
	USB_DPRINTF_L3(PRINT_MASK_DUMPING, uhcip->uhci_log_hdl,
	    "\tBytes Pending   = %d", td->tw->tw_bytes_pending);
	USB_DPRINTF_L3(PRINT_MASK_DUMPING, uhcip->uhci_log_hdl,
	    "Queue Head Details:");
	uhci_print_qh(uhcip, td->tw->tw_pipe_private->pp_qh);

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


static void
uhci_print_qh(uhci_state_t *uhcip, queue_head_t *qh)
{
	uint_t	*ptr = (uint_t *)qh;

	USB_DPRINTF_L3(PRINT_MASK_DUMPING, uhcip->uhci_log_hdl,
	    "\tLink Ptr = %x Element Ptr = %x", ptr[0], ptr[1]);
}
#endif
