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
 * Open Host Controller Driver (OHCI)
 *
 * The USB Open Host Controller driver is a software driver which interfaces
 * to the Universal Serial Bus layer (USBA) and the USB Open Host Controller.
 * The interface to USB Open Host Controller is defined by the OpenHCI	Host
 * Controller Interface.
 *
 * NOTE:
 *
 * Currently OHCI driver does not support the following features
 *
 * - Handle request with multiple TDs under short xfer conditions except for
 *   bulk transfers.
 */
#include <sys/usb/hcd/openhci/ohcid.h>

#include <sys/disp.h>
#include <sys/strsun.h>

/* Pointer to the state structure */
static void *ohci_statep;

int force_ohci_off = 1;

/* Number of instances */
#define	OHCI_INSTS	1

/* Adjustable variables for the size of the pools */
int ohci_ed_pool_size = OHCI_ED_POOL_SIZE;
int ohci_td_pool_size = OHCI_TD_POOL_SIZE;

/*
 * Initialize the values which are used for setting up head pointers for
 * the 32ms scheduling lists which starts from the HCCA.
 */
static uchar_t ohci_index[NUM_INTR_ED_LISTS / 2] = {0x0, 0x8, 0x4, 0xc,
						0x2, 0xa, 0x6, 0xe,
						0x1, 0x9, 0x5, 0xd,
						0x3, 0xb, 0x7, 0xf};
/* Debugging information */
uint_t ohci_errmask	= (uint_t)PRINT_MASK_ALL;
uint_t ohci_errlevel	= USB_LOG_L2;
uint_t ohci_instance_debug = (uint_t)-1;

/*
 * OHCI MSI tunable:
 *
 * By default MSI is enabled on all supported platforms.
 */
boolean_t ohci_enable_msi = B_TRUE;

/*
 * HCDI entry points
 *
 * The Host Controller Driver Interfaces (HCDI) are the software interfaces
 * between the Universal Serial Bus Driver (USBA) and the Host	Controller
 * Driver (HCD). The HCDI interfaces or entry points are subject to change.
 */
static int	ohci_hcdi_pipe_open(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_pipe_close(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_pipe_reset(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
static void	ohci_hcdi_pipe_reset_data_toggle(
				usba_pipe_handle_data_t	*ph);
static int	ohci_hcdi_pipe_ctrl_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_bulk_transfer_size(
				usba_device_t		*usba_device,
				size_t			*size);
static int	ohci_hcdi_pipe_bulk_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_bulk_req_t		*bulk_reqp,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_pipe_intr_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_req,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_pipe_stop_intr_polling(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_get_current_frame_number(
				usba_device_t		*usba_device,
				usb_frame_number_t	*frame_number);
static int	ohci_hcdi_get_max_isoc_pkts(
				usba_device_t		*usba_device,
				uint_t		*max_isoc_pkts_per_request);
static int	ohci_hcdi_pipe_isoc_xfer(
				usba_pipe_handle_data_t	*ph,
				usb_isoc_req_t		*isoc_reqp,
				usb_flags_t		usb_flags);
static int	ohci_hcdi_pipe_stop_isoc_polling(
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);

/*
 * Internal Function Prototypes
 */

/* Host Controller Driver (HCD) initialization functions */
static void	ohci_set_dma_attributes(ohci_state_t	*ohcip);
static int	ohci_allocate_pools(ohci_state_t	*ohcip);
static void	ohci_decode_ddi_dma_addr_bind_handle_result(
				ohci_state_t		*ohcip,
				int			result);
static int	ohci_map_regs(ohci_state_t		*ohcip);
static int	ohci_register_intrs_and_init_mutex(
				ohci_state_t		*ohcip);
static int	ohci_add_intrs(ohci_state_t		*ohcip,
				int			intr_type);
static int	ohci_init_ctlr(ohci_state_t		*ohcip);
static int	ohci_init_hcca(ohci_state_t		*ohcip);
static void	ohci_build_interrupt_lattice(
				ohci_state_t		*ohcip);
static int	ohci_take_control(ohci_state_t		*ohcip);
static usba_hcdi_ops_t *ohci_alloc_hcdi_ops(
				ohci_state_t		*ohcip);

/* Host Controller Driver (HCD) deinitialization functions */
static int	ohci_cleanup(ohci_state_t		*ohcip);
static void	ohci_rem_intrs(ohci_state_t		*ohcip);
static int	ohci_cpr_suspend(ohci_state_t		*ohcip);
static int	ohci_cpr_resume(ohci_state_t		*ohcip);

/* Bandwidth Allocation functions */
static int	ohci_allocate_bandwidth(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			*node);
static void	ohci_deallocate_bandwidth(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph);
static int	ohci_compute_total_bandwidth(
				usb_ep_descr_t		*endpoint,
				usb_port_status_t	port_status,
				uint_t			*bandwidth);
static int	ohci_adjust_polling_interval(
				ohci_state_t		*ohcip,
				usb_ep_descr_t		*endpoint,
				usb_port_status_t	port_status);
static uint_t	ohci_lattice_height(uint_t		interval);
static uint_t	ohci_lattice_parent(uint_t		node);
static uint_t	ohci_leftmost_leaf(uint_t		node,
				uint_t			height);
static uint_t	ohci_hcca_intr_index(
				uint_t			node);
static uint_t	ohci_hcca_leaf_index(
				uint_t			leaf);
static uint_t	ohci_pow_2(uint_t x);
static uint_t	ohci_log_2(uint_t x);

/* Endpoint Descriptor (ED) related functions */
static uint_t	ohci_unpack_endpoint(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph);
static void	ohci_insert_ed(ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph);
static void	ohci_insert_ctrl_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_insert_bulk_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_insert_intr_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_insert_isoc_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_modify_sKip_bit(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				skip_bit_t		action,
				usb_flags_t		flag);
static void	ohci_remove_ed(ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_remove_ctrl_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_remove_bulk_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_remove_periodic_ed(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_insert_ed_on_reclaim_list(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_detach_ed_from_list(
				ohci_state_t		*ohcip,
				ohci_ed_t		*ept,
				uint_t			ept_type);
static ohci_ed_t *ohci_ed_iommu_to_cpu(
				ohci_state_t		*ohcip,
				uintptr_t		addr);

/* Transfer Descriptor (TD) related functions */
static int	ohci_initialize_dummy(ohci_state_t	*ohcip,
				ohci_ed_t		*ept);
static ohci_trans_wrapper_t *ohci_allocate_ctrl_resources(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				usb_ctrl_req_t		*ctrl_reqp,
				usb_flags_t		usb_flags);
static void	ohci_insert_ctrl_req(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp,
				ohci_trans_wrapper_t	*tw,
				usb_flags_t		usb_flags);
static ohci_trans_wrapper_t *ohci_allocate_bulk_resources(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				usb_bulk_req_t		*bulk_reqp,
				usb_flags_t		usb_flags);
static void	ohci_insert_bulk_req(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_bulk_req_t		*bulk_reqp,
				ohci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
static int	ohci_start_pipe_polling(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
static void	ohci_set_periodic_pipe_polling(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph);
static ohci_trans_wrapper_t *ohci_allocate_intr_resources(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_reqp,
				usb_flags_t		usb_flags);
static void	ohci_insert_intr_req(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
static int	ohci_stop_periodic_pipe_polling(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
static ohci_trans_wrapper_t *ohci_allocate_isoc_resources(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_isoc_req_t		*isoc_reqp,
				usb_flags_t		usb_flags);
static int	ohci_insert_isoc_req(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				uint_t			flags);
static int	ohci_insert_hc_td(ohci_state_t		*ohcip,
				uint_t			hctd_ctrl,
				uint32_t		hctd_dma_offs,
				size_t			hctd_length,
				uint32_t		hctd_ctrl_phase,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);
static ohci_td_t *ohci_allocate_td_from_pool(
				ohci_state_t		*ohcip);
static void	ohci_fill_in_td(ohci_state_t		*ohcip,
				ohci_td_t		*td,
				ohci_td_t		*new_dummy,
				uint_t			hctd_ctrl,
				uint32_t		hctd_dma_offs,
				size_t			hctd_length,
				uint32_t		hctd_ctrl_phase,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);
static void	ohci_init_itd(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw,
				uint_t			hctd_ctrl,
				uint32_t		index,
				ohci_td_t		*td);
static int	ohci_insert_td_with_frame_number(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*current_td,
				ohci_td_t		*dummy_td);
static void	ohci_insert_td_on_tw(ohci_state_t	*ohcip,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td);
static void	ohci_done_list_tds(ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph);

/* Transfer Wrapper (TW) functions */
static ohci_trans_wrapper_t  *ohci_create_transfer_wrapper(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				size_t			length,
				uint_t			usb_flags);
static ohci_trans_wrapper_t  *ohci_create_isoc_transfer_wrapper(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				size_t			length,
				usb_isoc_pkt_descr_t	*descr,
				ushort_t		pkt_count,
				size_t			td_count,
				uint_t			usb_flags);
int	ohci_allocate_tds_for_tw(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw,
				size_t			td_count);
static ohci_trans_wrapper_t  *ohci_allocate_tw_resources(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				size_t			length,
				usb_flags_t		usb_flags,
				size_t			td_count);
static void	ohci_free_tw_tds_resources(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw);
static void	ohci_start_xfer_timer(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);
static void	ohci_stop_xfer_timer(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw,
				uint_t			flag);
static void	ohci_xfer_timeout_handler(void		*arg);
static void	ohci_remove_tw_from_timeout_list(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw);
static void	ohci_start_timer(ohci_state_t		*ohcip);
static void	ohci_free_dma_resources(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph);
static void	ohci_free_tw(ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw);
static int	ohci_tw_rebind_cookie(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);

/* Interrupt Handling functions */
static uint_t	ohci_intr(caddr_t			arg1,
				caddr_t			arg2);
static void	ohci_handle_missed_intr(
				ohci_state_t		*ohcip);
static void	ohci_handle_ue(ohci_state_t		*ohcip);
static void	ohci_handle_endpoint_reclaimation(
				ohci_state_t		*ohcip);
static void	ohci_traverse_done_list(
				ohci_state_t		*ohcip,
				ohci_td_t		*head_done_list);
static ohci_td_t *ohci_reverse_done_list(
				ohci_state_t		*ohcip,
				ohci_td_t		*head_done_list);
static usb_cr_t	ohci_parse_error(ohci_state_t		*ohcip,
				ohci_td_t		*td);
static void	ohci_parse_isoc_error(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td);
static usb_cr_t ohci_check_for_error(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td,
				uint_t			ctrl);
static void	ohci_handle_error(
				ohci_state_t		*ohcip,
				ohci_td_t		*td,
				usb_cr_t		error);
static int	ohci_cleanup_data_underrun(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td);
static void	ohci_handle_normal_td(
				ohci_state_t		*ohcip,
				ohci_td_t		*td,
				ohci_trans_wrapper_t	*tw);
static void	ohci_handle_ctrl_td(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td,
				void			*);
static void	ohci_handle_bulk_td(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td,
				void			*);
static void	ohci_handle_intr_td(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td,
				void			*);
static void	ohci_handle_one_xfer_completion(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw);
static void	ohci_handle_isoc_td(ohci_state_t	*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td,
				void			*);
static void	ohci_sendup_td_message(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td,
				usb_cr_t		error);
static int	ohci_check_done_head(
				ohci_state_t *ohcip,
				ohci_td_t		*done_head);

/* Miscillaneous functions */
static void	ohci_cpr_cleanup(
				ohci_state_t		*ohcip);
static usb_req_attrs_t ohci_get_xfer_attrs(ohci_state_t *ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);
static int	ohci_allocate_periodic_in_resource(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
static int	ohci_wait_for_sof(
				ohci_state_t		*ohcip);
static void	ohci_pipe_cleanup(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph);
static void	ohci_wait_for_transfers_completion(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_check_for_transfers_completion(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp);
static void	ohci_save_data_toggle(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph);
static void	ohci_restore_data_toggle(ohci_state_t	*ohcip,
				usba_pipe_handle_data_t	*ph);
static void	ohci_deallocate_periodic_in_resource(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);
static void	ohci_do_client_periodic_in_req_callback(
				ohci_state_t		*ohcip,
				ohci_pipe_private_t	*pp,
				usb_cr_t		completion_reason);
static void	ohci_hcdi_callback(
				usba_pipe_handle_data_t	*ph,
				ohci_trans_wrapper_t	*tw,
				usb_cr_t		completion_reason);

/* Kstat Support */
static void	ohci_create_stats(ohci_state_t		*ohcip);
static void	ohci_destroy_stats(ohci_state_t		*ohcip);
static void	ohci_do_byte_stats(
				ohci_state_t		*ohcip,
				size_t			len,
				uint8_t			attr,
				uint8_t			addr);
static void	ohci_do_intrs_stats(
				ohci_state_t		*ohcip,
				int			val);
static void	ohci_print_op_regs(ohci_state_t		*ohcip);
static void	ohci_print_ed(ohci_state_t		*ohcip,
				ohci_ed_t		*ed);
static void	ohci_print_td(ohci_state_t		*ohcip,
				ohci_td_t		*td);

/* extern */
int usba_hubdi_root_hub_power(dev_info_t *dip, int comp, int level);

/*
 * Device operations (dev_ops) entries function prototypes.
 *
 * We use the hub cbops since all nexus ioctl operations defined so far will
 * be executed by the root hub. The following are the Host Controller Driver
 * (HCD) entry points.
 *
 * the open/close/ioctl functions call the corresponding usba_hubdi_*
 * calls after looking up the dip thru the dev_t.
 */
static int	ohci_open(dev_t	*devp, int flags, int otyp, cred_t *credp);
static int	ohci_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int	ohci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
				cred_t *credp, int *rvalp);

static int	ohci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	ohci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	ohci_quiesce(dev_info_t *dip);

static int	ohci_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
				void *arg, void **result);

static struct cb_ops ohci_cb_ops = {
	ohci_open,			/* Open */
	ohci_close,			/* Close */
	nodev,				/* Strategy */
	nodev,				/* Print */
	nodev,				/* Dump */
	nodev,				/* Read */
	nodev,				/* Write */
	ohci_ioctl,			/* Ioctl */
	nodev,				/* Devmap */
	nodev,				/* Mmap */
	nodev,				/* Segmap */
	nochpoll,			/* Poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* Streamtab */
	D_MP				/* Driver compatibility flag */
};

static struct dev_ops ohci_ops = {
	DEVO_REV,			/* Devo_rev */
	0,				/* Refcnt */
	ohci_info,			/* Info */
	nulldev,			/* Identify */
	nulldev,			/* Probe */
	ohci_attach,			/* Attach */
	ohci_detach,			/* Detach */
	nodev,				/* Reset */
	&ohci_cb_ops,			/* Driver operations */
	&usba_hubdi_busops,		/* Bus operations */
	usba_hubdi_root_hub_power,	/* Power */
	ohci_quiesce,			/* Quiesce */
};

/*
 * The USBA library must be loaded for this driver.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"USB OpenHCI Driver",	/* Name of the module. */
	&ohci_ops,		/* Driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


int
_init(void)
{
	int error;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&ohci_statep, sizeof (ohci_state_t),
	    OHCI_INSTS)) != 0) {
		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ohci_statep);
	}

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		/* Release per module resources */
		ddi_soft_state_fini(&ohci_statep);
	}

	return (error);
}


/*
 * Host Controller Driver (HCD) entry points
 */

/*
 * ohci_attach:
 */
static int
ohci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	ohci_state_t		*ohcip = NULL;
	usba_hcdi_register_args_t hcdi_args;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		ohcip = ohci_obtain_state(dip);

		return (ohci_cpr_resume(ohcip));
	default:
		return (DDI_FAILURE);
	}

	/* Get the instance and create soft state */
	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ohci_statep, instance) != 0) {

		return (DDI_FAILURE);
	}

	ohcip = ddi_get_soft_state(ohci_statep, instance);
	if (ohcip == NULL) {

		return (DDI_FAILURE);
	}

	ohcip->ohci_flags = OHCI_ATTACH;

	ohcip->ohci_log_hdl = usb_alloc_log_hdl(dip, "ohci", &ohci_errlevel,
	    &ohci_errmask, &ohci_instance_debug, 0);

	ohcip->ohci_flags |= OHCI_ZALLOC;

	/* Set host controller soft state to initilization */
	ohcip->ohci_hc_soft_state = OHCI_CTLR_INIT_STATE;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohcip = 0x%p", (void *)ohcip);

	/* Initialize the DMA attributes */
	ohci_set_dma_attributes(ohcip);

	/* Save the dip and instance */
	ohcip->ohci_dip = dip;
	ohcip->ohci_instance = instance;

	/* Initialize the kstat structures */
	ohci_create_stats(ohcip);

	/* Create the td and ed pools */
	if (ohci_allocate_pools(ohcip) != DDI_SUCCESS) {
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}

	/* Map the registers */
	if (ohci_map_regs(ohcip) != DDI_SUCCESS) {
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}

	/* Get the ohci chip vendor and device id */
	ohcip->ohci_vendor_id = pci_config_get16(
	    ohcip->ohci_config_handle, PCI_CONF_VENID);
	ohcip->ohci_device_id = pci_config_get16(
	    ohcip->ohci_config_handle, PCI_CONF_DEVID);
	ohcip->ohci_rev_id = pci_config_get8(
	    ohcip->ohci_config_handle, PCI_CONF_REVID);

	/* Register interrupts */
	if (ohci_register_intrs_and_init_mutex(ohcip) != DDI_SUCCESS) {
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Initialize the controller */
	if (ohci_init_ctlr(ohcip) != DDI_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}

	/*
	 * At this point, the hardware wiil be okay.
	 * Initialize the usba_hcdi structure
	 */
	ohcip->ohci_hcdi_ops = ohci_alloc_hcdi_ops(ohcip);

	mutex_exit(&ohcip->ohci_int_mutex);

	/*
	 * Make this HCD instance known to USBA
	 * (dma_attr must be passed for USBA busctl's)
	 */
	hcdi_args.usba_hcdi_register_version = HCDI_REGISTER_VERSION;
	hcdi_args.usba_hcdi_register_dip = dip;
	hcdi_args.usba_hcdi_register_ops = ohcip->ohci_hcdi_ops;
	hcdi_args.usba_hcdi_register_dma_attr = &ohcip->ohci_dma_attr;

	/*
	 * Priority and iblock_cookie are one and the same
	 * (However, retaining hcdi_soft_iblock_cookie for now
	 * assigning it w/ priority. In future all iblock_cookie
	 * could just go)
	 */
	hcdi_args.usba_hcdi_register_iblock_cookie =
	    (ddi_iblock_cookie_t)(uintptr_t)ohcip->ohci_intr_pri;

	if (usba_hcdi_register(&hcdi_args, 0) != DDI_SUCCESS) {
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}
	ohcip->ohci_flags |= OHCI_USBAREG;

	mutex_enter(&ohcip->ohci_int_mutex);

	if ((ohci_init_root_hub(ohcip)) != USB_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	/* Finally load the root hub driver */
	if (ohci_load_root_hub_driver(ohcip) != USB_SUCCESS) {
		(void) ohci_cleanup(ohcip);

		return (DDI_FAILURE);
	}
	ohcip->ohci_flags |= OHCI_RHREG;

	/* Display information in the banner */
	ddi_report_dev(dip);

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Reset the ohci initilization flag */
	ohcip->ohci_flags &= ~OHCI_ATTACH;

	/* Print the Host Control's Operational registers */
	ohci_print_op_regs(ohcip);

	/* For RIO we need to call pci_report_pmcap */
	if (OHCI_IS_RIO(ohcip)) {

		(void) pci_report_pmcap(dip, PCI_PM_IDLESPEED, (void *)4000);
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_attach: dip = 0x%p done", (void *)dip);

	return (DDI_SUCCESS);
}


/*
 * ohci_detach:
 */
int
ohci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ohci_state_t		*ohcip = ohci_obtain_state(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl, "ohci_detach:");

	switch (cmd) {
	case DDI_DETACH:

		return (ohci_cleanup(ohcip));

	case DDI_SUSPEND:

		return (ohci_cpr_suspend(ohcip));
	default:

		return (DDI_FAILURE);
	}
}


/*
 * ohci_info:
 */
/* ARGSUSED */
static int
ohci_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t			dev;
	ohci_state_t		*ohcip;
	int			instance;
	int			error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = OHCI_UNIT(dev);
		ohcip = ddi_get_soft_state(ohci_statep, instance);
		if (ohcip != NULL) {
			*result = (void *)ohcip->ohci_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = OHCI_UNIT(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}


/*
 * cb_ops entry points
 */
static dev_info_t *
ohci_get_dip(dev_t dev)
{
	int		instance = OHCI_UNIT(dev);
	ohci_state_t	*ohcip = ddi_get_soft_state(ohci_statep, instance);

	if (ohcip) {

		return (ohcip->ohci_dip);
	} else {

		return (NULL);
	}
}


static int
ohci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t	*dip = ohci_get_dip(*devp);

	return (usba_hubdi_open(dip, devp, flags, otyp, credp));
}


static int
ohci_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t	*dip = ohci_get_dip(dev);

	return (usba_hubdi_close(dip, dev, flag, otyp, credp));
}


static int
ohci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	dev_info_t	*dip = ohci_get_dip(dev);

	return (usba_hubdi_ioctl(dip,
	    dev, cmd, arg, mode, credp, rvalp));
}


/*
 * Host Controller Driver (HCD) initialization functions
 */

/*
 * ohci_set_dma_attributes:
 *
 * Set the limits in the DMA attributes structure. Most of the values used
 * in the  DMA limit structres are the default values as specified by  the
 * Writing PCI device drivers document.
 */
static void
ohci_set_dma_attributes(ohci_state_t	*ohcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_set_dma_attributes:");

	/* Initialize the DMA attributes */
	ohcip->ohci_dma_attr.dma_attr_version = DMA_ATTR_V0;
	ohcip->ohci_dma_attr.dma_attr_addr_lo = 0x00000000ull;
	ohcip->ohci_dma_attr.dma_attr_addr_hi = 0xfffffffeull;

	/* 32 bit addressing */
	ohcip->ohci_dma_attr.dma_attr_count_max = OHCI_DMA_ATTR_COUNT_MAX;

	/* Byte alignment */
	ohcip->ohci_dma_attr.dma_attr_align = OHCI_DMA_ATTR_ALIGNMENT;

	/*
	 * Since PCI  specification is byte alignment, the
	 * burstsize field should be set to 1 for PCI devices.
	 */
	ohcip->ohci_dma_attr.dma_attr_burstsizes = 0x1;

	ohcip->ohci_dma_attr.dma_attr_minxfer = 0x1;
	ohcip->ohci_dma_attr.dma_attr_maxxfer = OHCI_DMA_ATTR_MAX_XFER;
	ohcip->ohci_dma_attr.dma_attr_seg = 0xffffffffull;
	ohcip->ohci_dma_attr.dma_attr_sgllen = 1;
	ohcip->ohci_dma_attr.dma_attr_granular = OHCI_DMA_ATTR_GRANULAR;
	ohcip->ohci_dma_attr.dma_attr_flags = 0;
}


/*
 * ohci_allocate_pools:
 *
 * Allocate the system memory for the Endpoint Descriptor (ED) and for the
 * Transfer Descriptor (TD) pools. Both ED and TD structures must be aligned
 * to a 16 byte boundary.
 */
static int
ohci_allocate_pools(ohci_state_t	*ohcip)
{
	ddi_device_acc_attr_t		dev_attr;
	size_t				real_length;
	int				result;
	uint_t				ccount;
	int				i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_allocate_pools:");

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version	= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder	= DDI_STRICTORDER_ACC;

	/* Byte alignment to TD alignment */
	ohcip->ohci_dma_attr.dma_attr_align = OHCI_DMA_ATTR_TD_ALIGNMENT;

	/* Allocate the TD pool DMA handle */
	if (ddi_dma_alloc_handle(ohcip->ohci_dip, &ohcip->ohci_dma_attr,
	    DDI_DMA_SLEEP, 0,
	    &ohcip->ohci_td_pool_dma_handle) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	/* Allocate the memory for the TD pool */
	if (ddi_dma_mem_alloc(ohcip->ohci_td_pool_dma_handle,
	    ohci_td_pool_size * sizeof (ohci_td_t),
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    0,
	    (caddr_t *)&ohcip->ohci_td_pool_addr,
	    &real_length,
	    &ohcip->ohci_td_pool_mem_handle)) {

		return (DDI_FAILURE);
	}

	/* Map the TD pool into the I/O address space */
	result = ddi_dma_addr_bind_handle(
	    ohcip->ohci_td_pool_dma_handle,
	    NULL,
	    (caddr_t)ohcip->ohci_td_pool_addr,
	    real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ohcip->ohci_td_pool_cookie,
	    &ccount);

	bzero((void *)ohcip->ohci_td_pool_addr,
	    ohci_td_pool_size * sizeof (ohci_td_t));

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_allocate_pools: More than 1 cookie");

			return (DDI_FAILURE);
		}
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_allocate_pools: Result = %d", result);

		ohci_decode_ddi_dma_addr_bind_handle_result(ohcip, result);

		return (DDI_FAILURE);
	}

	/*
	 * DMA addresses for TD pools are bound
	 */
	ohcip->ohci_dma_addr_bind_flag |= OHCI_TD_POOL_BOUND;

	/* Initialize the TD pool */
	for (i = 0; i < ohci_td_pool_size; i ++) {
		Set_TD(ohcip->ohci_td_pool_addr[i].hctd_state, HC_TD_FREE);
	}

	/* Byte alignment to ED alignment */
	ohcip->ohci_dma_attr.dma_attr_align = OHCI_DMA_ATTR_ED_ALIGNMENT;

	/* Allocate the ED pool DMA handle */
	if (ddi_dma_alloc_handle(ohcip->ohci_dip,
	    &ohcip->ohci_dma_attr,
	    DDI_DMA_SLEEP,
	    0,
	    &ohcip->ohci_ed_pool_dma_handle) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	/* Allocate the memory for the ED pool */
	if (ddi_dma_mem_alloc(ohcip->ohci_ed_pool_dma_handle,
	    ohci_ed_pool_size * sizeof (ohci_ed_t),
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    0,
	    (caddr_t *)&ohcip->ohci_ed_pool_addr,
	    &real_length,
	    &ohcip->ohci_ed_pool_mem_handle) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	result = ddi_dma_addr_bind_handle(ohcip->ohci_ed_pool_dma_handle,
	    NULL,
	    (caddr_t)ohcip->ohci_ed_pool_addr,
	    real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ohcip->ohci_ed_pool_cookie,
	    &ccount);

	bzero((void *)ohcip->ohci_ed_pool_addr,
	    ohci_ed_pool_size * sizeof (ohci_ed_t));

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_allocate_pools: More than 1 cookie");

			return (DDI_FAILURE);
		}
	} else {
		ohci_decode_ddi_dma_addr_bind_handle_result(ohcip, result);

		return (DDI_FAILURE);
	}

	/*
	 * DMA addresses for ED pools are bound
	 */
	ohcip->ohci_dma_addr_bind_flag |= OHCI_ED_POOL_BOUND;

	/* Initialize the ED pool */
	for (i = 0; i < ohci_ed_pool_size; i ++) {
		Set_ED(ohcip->ohci_ed_pool_addr[i].hced_state, HC_EPT_FREE);
	}

	return (DDI_SUCCESS);
}


/*
 * ohci_decode_ddi_dma_addr_bind_handle_result:
 *
 * Process the return values of ddi_dma_addr_bind_handle()
 */
static void
ohci_decode_ddi_dma_addr_bind_handle_result(
	ohci_state_t	*ohcip,
	int		result)
{
	USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_decode_ddi_dma_addr_bind_handle_result:");

	switch (result) {
	case DDI_DMA_PARTIAL_MAP:
		USB_DPRINTF_L2(PRINT_MASK_ALL, ohcip->ohci_log_hdl,
		    "Partial transfers not allowed");
		break;
	case DDI_DMA_INUSE:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ohcip->ohci_log_hdl,
		    "Handle is in use");
		break;
	case DDI_DMA_NORESOURCES:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ohcip->ohci_log_hdl,
		    "No resources");
		break;
	case DDI_DMA_NOMAPPING:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ohcip->ohci_log_hdl,
		    "No mapping");
		break;
	case DDI_DMA_TOOBIG:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ohcip->ohci_log_hdl,
		    "Object is too big");
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ALL,	ohcip->ohci_log_hdl,
		    "Unknown dma error");
	}
}


/*
 * ohci_map_regs:
 *
 * The Host Controller (HC) contains a set of on-chip operational registers
 * and which should be mapped into a non-cacheable portion of the  system
 * addressable space.
 */
static int
ohci_map_regs(ohci_state_t	*ohcip)
{
	ddi_device_acc_attr_t	attr;
	uint16_t		cmd_reg;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl, "ohci_map_regs:");

	/* The host controller will be little endian */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Map in operational registers */
	if (ddi_regs_map_setup(ohcip->ohci_dip, 1,
	    (caddr_t *)&ohcip->ohci_regsp, 0,
	    sizeof (ohci_regs_t), &attr,
	    &ohcip->ohci_regs_handle) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_map_regs: Map setup error");

		return (DDI_FAILURE);
	}

	if (pci_config_setup(ohcip->ohci_dip,
	    &ohcip->ohci_config_handle) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_map_regs: Config error");

		return (DDI_FAILURE);
	}

	/* Make sure Memory Access Enable and Master Enable are set */
	cmd_reg = pci_config_get16(ohcip->ohci_config_handle, PCI_CONF_COMM);

	if (!(cmd_reg & PCI_COMM_MAE)) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_map_regs: Memory base address access disabled");

		return (DDI_FAILURE);
	}

	cmd_reg |= (PCI_COMM_MAE | PCI_COMM_ME);

	pci_config_put16(ohcip->ohci_config_handle, PCI_CONF_COMM, cmd_reg);

	return (DDI_SUCCESS);
}

/*
 * The following simulated polling is for debugging purposes only.
 * It is activated on x86 by setting usb-polling=true in GRUB or ohci.conf.
 */
static int
ohci_is_polled(dev_info_t *dip)
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
ohci_poll_intr(void *arg)
{
	/* poll every millisecond */
	for (;;) {
		(void) ohci_intr(arg, NULL);
		delay(drv_usectohz(1000));
	}
}

/*
 * ohci_register_intrs_and_init_mutex:
 *
 * Register interrupts and initialize each mutex and condition variables
 */
static int
ohci_register_intrs_and_init_mutex(ohci_state_t	*ohcip)
{
	int	intr_types;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_register_intrs_and_init_mutex:");

	/*
	 * Sometimes the OHCI controller of ULI1575 southbridge
	 * could not receive SOF intrs when enable MSI. Hence
	 * MSI is disabled for this chip.
	 */
	if ((ohcip->ohci_vendor_id == PCI_ULI1575_VENID) &&
	    (ohcip->ohci_device_id == PCI_ULI1575_DEVID)) {
		ohcip->ohci_msi_enabled = B_FALSE;
	} else {
		ohcip->ohci_msi_enabled = ohci_enable_msi;
	}

	if (ohci_is_polled(ohcip->ohci_dip)) {
		extern pri_t maxclsyspri;

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_register_intrs_and_init_mutex: "
		    "running in simulated polled mode");

		(void) thread_create(NULL, 0, ohci_poll_intr, ohcip, 0, &p0,
		    TS_RUN, maxclsyspri);

		goto skip_intr;
	}

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(ohcip->ohci_dip,
	    &intr_types) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_register_intrs_and_init_mutex: "
		    "ddi_intr_get_supported_types failed");

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_register_intrs_and_init_mutex: "
	    "supported interrupt types 0x%x", intr_types);

	if ((intr_types & DDI_INTR_TYPE_MSI) && ohcip->ohci_msi_enabled) {
		if (ohci_add_intrs(ohcip, DDI_INTR_TYPE_MSI)
		    != DDI_SUCCESS) {
			USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_register_intrs_and_init_mutex: MSI "
			    "registration failed, trying FIXED interrupt \n");
		} else {
			USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_register_intrs_and_init_mutex: "
			    "Using MSI interrupt type\n");

			ohcip->ohci_intr_type = DDI_INTR_TYPE_MSI;
			ohcip->ohci_flags |= OHCI_INTR;
		}
	}

	if ((!(ohcip->ohci_flags & OHCI_INTR)) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		if (ohci_add_intrs(ohcip, DDI_INTR_TYPE_FIXED)
		    != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_register_intrs_and_init_mutex: "
			    "FIXED interrupt registration failed\n");

			return (DDI_FAILURE);
		}

		USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_register_intrs_and_init_mutex: "
		    "Using FIXED interrupt type\n");

		ohcip->ohci_intr_type = DDI_INTR_TYPE_FIXED;
		ohcip->ohci_flags |= OHCI_INTR;
	}

skip_intr:
	/* Create prototype for SOF condition variable */
	cv_init(&ohcip->ohci_SOF_cv, NULL, CV_DRIVER, NULL);

	/* Semaphore to serialize opens and closes */
	sema_init(&ohcip->ohci_ocsem, 1, NULL, SEMA_DRIVER, NULL);

	return (DDI_SUCCESS);
}


/*
 * ohci_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
ohci_add_intrs(ohci_state_t *ohcip, int intr_type)
{
	int	actual, avail, intr_size, count = 0;
	int	i, flag, ret;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_add_intrs: interrupt type 0x%x", intr_type);

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(ohcip->ohci_dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: ddi_intr_get_nintrs() failure, "
		    "ret: %d, count: %d", ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(ohcip->ohci_dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: ddi_intr_get_navail() failure, "
		    "ret: %d, count: %d", ret, count);

		return (DDI_FAILURE);
	}

	if (avail < count) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: ohci_add_intrs: nintrs () "
		    "returned %d, navail returned %d\n", count, avail);
	}

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	ohcip->ohci_htable = kmem_zalloc(intr_size, KM_SLEEP);

	flag = (intr_type == DDI_INTR_TYPE_MSI) ?
	    DDI_INTR_ALLOC_STRICT:DDI_INTR_ALLOC_NORMAL;

	/* call ddi_intr_alloc() */
	ret = ddi_intr_alloc(ohcip->ohci_dip, ohcip->ohci_htable,
	    intr_type, 0, count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: ddi_intr_alloc() failed %d", ret);

		kmem_free(ohcip->ohci_htable, intr_size);

		return (DDI_FAILURE);
	}

	if (actual < count) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: Requested: %d, Received: %d\n",
		    count, actual);

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ohcip->ohci_htable[i]);

		kmem_free(ohcip->ohci_htable, intr_size);

		return (DDI_FAILURE);
	}

	ohcip->ohci_intr_cnt = actual;

	if ((ret = ddi_intr_get_pri(ohcip->ohci_htable[0],
	    &ohcip->ohci_intr_pri)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: ddi_intr_get_pri() failed %d", ret);

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ohcip->ohci_htable[i]);

		kmem_free(ohcip->ohci_htable, intr_size);

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_add_intrs: Supported Interrupt priority 0x%x",
	    ohcip->ohci_intr_pri);

	/* Test for high level mutex */
	if (ohcip->ohci_intr_pri >= ddi_intr_get_hilevel_pri()) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: Hi level interrupt not supported");

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ohcip->ohci_htable[i]);

		kmem_free(ohcip->ohci_htable, intr_size);

		return (DDI_FAILURE);
	}

	/* Initialize the mutex */
	mutex_init(&ohcip->ohci_int_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ohcip->ohci_intr_pri));

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(ohcip->ohci_htable[i],
		    ohci_intr, (caddr_t)ohcip,
		    (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_add_intrs: ddi_intr_add_handler() "
			    "failed %d", ret);

			for (i = 0; i < actual; i++)
				(void) ddi_intr_free(ohcip->ohci_htable[i]);

			mutex_destroy(&ohcip->ohci_int_mutex);
			kmem_free(ohcip->ohci_htable, intr_size);

			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(ohcip->ohci_htable[0],
	    &ohcip->ohci_intr_cap)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_add_intrs: ddi_intr_get_cap() failed %d", ret);

		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(ohcip->ohci_htable[i]);
			(void) ddi_intr_free(ohcip->ohci_htable[i]);
		}

		mutex_destroy(&ohcip->ohci_int_mutex);
		kmem_free(ohcip->ohci_htable, intr_size);

		return (DDI_FAILURE);
	}

	/* Enable all interrupts */
	if (ohcip->ohci_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(ohcip->ohci_htable,
		    ohcip->ohci_intr_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < ohcip->ohci_intr_cnt; i++)
			(void) ddi_intr_enable(ohcip->ohci_htable[i]);
	}

	return (DDI_SUCCESS);
}


/*
 * ohci_init_ctlr:
 *
 * Initialize the Host Controller (HC).
 */
static int
ohci_init_ctlr(ohci_state_t	*ohcip)
{
	int			revision, curr_control, max_packet = 0;
	clock_t			sof_time_wait;
	int			retry = 0;
	int			ohci_frame_interval;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl, "ohci_init_ctlr:");

	if (ohci_take_control(ohcip) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_init_ctlr: ohci_take_control failed\n");

		return (DDI_FAILURE);
	}

	/*
	 * Soft reset the host controller.
	 *
	 * On soft reset, the ohci host controller moves to the
	 * USB Suspend state in which most of the ohci operational
	 * registers are reset except stated ones. The soft reset
	 * doesn't cause a reset to the ohci root hub and even no
	 * subsequent reset signaling should be asserterd to its
	 * down stream.
	 */
	Set_OpReg(hcr_cmd_status, HCR_STATUS_RESET);

	mutex_exit(&ohcip->ohci_int_mutex);
	/* Wait 10ms for reset to complete */
	delay(drv_usectohz(OHCI_RESET_TIMEWAIT));
	mutex_enter(&ohcip->ohci_int_mutex);

	/*
	 * Do hard reset the host controller.
	 *
	 * Now perform USB reset in order to reset the ohci root
	 * hub.
	 */
	Set_OpReg(hcr_control, HCR_CONTROL_RESET);

	/*
	 * According to Section 5.1.2.3 of the specification, the
	 * host controller will go into suspend state immediately
	 * after the reset.
	 */

	/* Verify the version number */
	revision = Get_OpReg(hcr_revision);

	if ((revision & HCR_REVISION_MASK) != HCR_REVISION_1_0) {

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_ctlr: Revision verified");

	/* hcca area need not be initialized on resume */
	if (ohcip->ohci_hc_soft_state == OHCI_CTLR_INIT_STATE) {

		/* Initialize the hcca area */
		if (ohci_init_hcca(ohcip) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}

	/*
	 * Workaround for ULI1575 chipset. Following OHCI Operational Memory
	 * Registers are not cleared to their default value on reset.
	 * Explicitly set the registers to default value.
	 */
	if (ohcip->ohci_vendor_id == PCI_ULI1575_VENID &&
	    ohcip->ohci_device_id == PCI_ULI1575_DEVID) {
		Set_OpReg(hcr_control, HCR_CONTROL_DEFAULT);
		Set_OpReg(hcr_intr_enable, HCR_INT_ENABLE_DEFAULT);
		Set_OpReg(hcr_HCCA, HCR_HCCA_DEFAULT);
		Set_OpReg(hcr_ctrl_head, HCR_CONTROL_HEAD_ED_DEFAULT);
		Set_OpReg(hcr_bulk_head, HCR_BULK_HEAD_ED_DEFAULT);
		Set_OpReg(hcr_frame_interval, HCR_FRAME_INTERVAL_DEFAULT);
		Set_OpReg(hcr_periodic_strt, HCR_PERIODIC_START_DEFAULT);
	}

	/* Set the HcHCCA to the physical address of the HCCA block */
	Set_OpReg(hcr_HCCA, (uint_t)ohcip->ohci_hcca_cookie.dmac_address);

	/*
	 * Set HcInterruptEnable to enable all interrupts except Root
	 * Hub Status change and SOF interrupts.
	 */
	Set_OpReg(hcr_intr_enable, HCR_INTR_SO | HCR_INTR_WDH |
	    HCR_INTR_RD | HCR_INTR_UE | HCR_INTR_FNO | HCR_INTR_MIE);

	/*
	 * For non-periodic transfers, reserve atleast for one low-speed
	 * device transaction. According to USB Bandwidth Analysis white
	 * paper and also as per OHCI Specification 1.0a, section 7.3.5,
	 * page 123, one low-speed transaction takes 0x628h full speed
	 * bits (197 bytes), which comes to around 13% of USB frame time.
	 *
	 * The periodic transfers will get around 87% of USB frame time.
	 */
	Set_OpReg(hcr_periodic_strt,
	    ((PERIODIC_XFER_STARTS * BITS_PER_BYTE) - 1));

	/* Save the contents of the Frame Interval Registers */
	ohcip->ohci_frame_interval = Get_OpReg(hcr_frame_interval);

	/*
	 * Initialize the FSLargestDataPacket value in the frame interval
	 * register. The controller compares the value of MaxPacketSize to
	 * this value to see if the entire packet may be sent out before
	 * the EOF.
	 */
	max_packet = ((((ohcip->ohci_frame_interval -
	    MAX_OVERHEAD) * 6) / 7) << HCR_FRME_FSMPS_SHFT);

	Set_OpReg(hcr_frame_interval,
	    (max_packet | ohcip->ohci_frame_interval));

	/*
	 * Sometimes the HcFmInterval register in OHCI controller does not
	 * maintain its value after the first write. This problem is found
	 * on ULI M1575 South Bridge. To workaround the hardware problem,
	 * check the value after write and retry if the last write failed.
	 */
	if (ohcip->ohci_vendor_id == PCI_ULI1575_VENID &&
	    ohcip->ohci_device_id == PCI_ULI1575_DEVID) {
		ohci_frame_interval = Get_OpReg(hcr_frame_interval);
		while ((ohci_frame_interval != (max_packet |
		    ohcip->ohci_frame_interval))) {
			if (retry >= 10) {
				USB_DPRINTF_L1(PRINT_MASK_ATTA,
				    ohcip->ohci_log_hdl, "Failed to program"
				    " Frame Interval Register.");

				return (DDI_FAILURE);
			}
			retry++;
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_init_ctlr: Failed to program Frame"
			    " Interval Register, retry=%d", retry);
			Set_OpReg(hcr_frame_interval,
			    (max_packet | ohcip->ohci_frame_interval));
			ohci_frame_interval = Get_OpReg(hcr_frame_interval);
		}
	}

	/* Begin sending SOFs */
	curr_control = Get_OpReg(hcr_control);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_ctlr: curr_control=0x%x", curr_control);

	/* Set the state to operational */
	curr_control = (curr_control &
	    (~HCR_CONTROL_HCFS)) | HCR_CONTROL_OPERAT;

	Set_OpReg(hcr_control, curr_control);

	ASSERT((Get_OpReg(hcr_control) &
	    HCR_CONTROL_HCFS) == HCR_CONTROL_OPERAT);

	/* Set host controller soft state to operational */
	ohcip->ohci_hc_soft_state = OHCI_CTLR_OPERATIONAL_STATE;

	/* Get the number of clock ticks to wait */
	sof_time_wait = drv_usectohz(OHCI_MAX_SOF_TIMEWAIT * 1000000);

	/* Clear ohci_sof_flag indicating waiting for SOF interrupt */
	ohcip->ohci_sof_flag = B_FALSE;

	/* Enable the SOF interrupt */
	Set_OpReg(hcr_intr_enable, HCR_INTR_SOF);

	ASSERT(Get_OpReg(hcr_intr_enable) & HCR_INTR_SOF);

	(void) cv_reltimedwait(&ohcip->ohci_SOF_cv,
	    &ohcip->ohci_int_mutex, sof_time_wait, TR_CLOCK_TICK);

	/* Wait for the SOF or timeout event */
	if (ohcip->ohci_sof_flag == B_FALSE) {

		/* Set host controller soft state to error */
		ohcip->ohci_hc_soft_state = OHCI_CTLR_ERROR_STATE;

		USB_DPRINTF_L0(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "No SOF interrupts have been received, this USB OHCI host"
		    "controller is unusable");
		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_ctlr: SOF's have started");

	return (DDI_SUCCESS);
}


/*
 * ohci_init_hcca:
 *
 * Allocate the system memory and initialize Host Controller Communication
 * Area (HCCA). The HCCA structure must be aligned to a 256-byte boundary.
 */
static int
ohci_init_hcca(ohci_state_t	*ohcip)
{
	ddi_device_acc_attr_t	dev_attr;
	size_t			real_length;
	uint_t			mask, ccount;
	int			result;
	uintptr_t		addr;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl, "ohci_init_hcca:");

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Byte alignment to HCCA alignment */
	ohcip->ohci_dma_attr.dma_attr_align = OHCI_DMA_ATTR_HCCA_ALIGNMENT;

	/* Create space for the HCCA block */
	if (ddi_dma_alloc_handle(ohcip->ohci_dip, &ohcip->ohci_dma_attr,
	    DDI_DMA_SLEEP,
	    0,
	    &ohcip->ohci_hcca_dma_handle)
	    != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(ohcip->ohci_hcca_dma_handle,
	    2 * sizeof (ohci_hcca_t),
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    0,
	    (caddr_t *)&ohcip->ohci_hccap,
	    &real_length,
	    &ohcip->ohci_hcca_mem_handle)) {

		return (DDI_FAILURE);
	}

	bzero((void *)ohcip->ohci_hccap, real_length);

	/* Figure out the alignment requirements */
	Set_OpReg(hcr_HCCA, 0xFFFFFFFF);

	/*
	 * Read the hcr_HCCA register until
	 * contenets are non-zero.
	 */
	mask = Get_OpReg(hcr_HCCA);

	mutex_exit(&ohcip->ohci_int_mutex);
	while (mask == 0) {
		delay(drv_usectohz(OHCI_TIMEWAIT));
		mask = Get_OpReg(hcr_HCCA);
	}
	mutex_enter(&ohcip->ohci_int_mutex);

	ASSERT(mask != 0);

	addr = (uintptr_t)ohcip->ohci_hccap;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_hcca: addr=0x%lx, mask=0x%x", addr, mask);

	while (addr & (~mask)) {
		addr++;
	}

	ohcip->ohci_hccap = (ohci_hcca_t *)addr;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_hcca: Real length %lu", real_length);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_hcca: virtual hcca 0x%p", (void *)ohcip->ohci_hccap);

	/* Map the whole HCCA into the I/O address space */
	result = ddi_dma_addr_bind_handle(ohcip->ohci_hcca_dma_handle,
	    NULL,
	    (caddr_t)ohcip->ohci_hccap,
	    real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL,
	    &ohcip->ohci_hcca_cookie,
	    &ccount);

	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
			    "ohci_init_hcca: More than 1 cookie");

			return (DDI_FAILURE);
		}
	} else {
		ohci_decode_ddi_dma_addr_bind_handle_result(ohcip, result);

		return (DDI_FAILURE);
	}

	/*
	 * DMA addresses for HCCA are bound
	 */
	ohcip->ohci_dma_addr_bind_flag |= OHCI_HCCA_DMA_BOUND;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_hcca: physical 0x%p",
	    (void *)(uintptr_t)ohcip->ohci_hcca_cookie.dmac_address);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_hcca: size %lu", ohcip->ohci_hcca_cookie.dmac_size);

	/* Initialize the interrupt lists */
	ohci_build_interrupt_lattice(ohcip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_init_hcca: End");

	return (DDI_SUCCESS);
}


/*
 * ohci_build_interrupt_lattice:
 *
 * Construct the interrupt lattice tree using static Endpoint Descriptors
 * (ED). This interrupt lattice tree will have total of 32 interrupt  ED
 * lists and the Host Controller (HC) processes one interrupt ED list in
 * every frame. The lower five bits of the current frame number indexes
 * into an array of 32 interrupt Endpoint Descriptor lists found in the
 * HCCA.
 */
static void
ohci_build_interrupt_lattice(ohci_state_t	*ohcip)
{
	ohci_ed_t	*list_array = ohcip->ohci_ed_pool_addr;
	int		half_list = NUM_INTR_ED_LISTS / 2;
	ohci_hcca_t	*hccap = ohcip->ohci_hccap;
	uintptr_t	addr;
	int		i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_build_interrupt_lattice:");

	/*
	 * Reserve the first 31 Endpoint Descriptor (ED) structures
	 * in the pool as static endpoints & these are required for
	 * constructing interrupt lattice tree.
	 */
	for (i = 0; i < NUM_STATIC_NODES; i++) {
		Set_ED(list_array[i].hced_ctrl, HC_EPT_sKip);

		Set_ED(list_array[i].hced_state, HC_EPT_STATIC);
	}

	/* Build the interrupt lattice tree */
	for (i = 0; i < half_list - 1; i++) {

		/*
		 * The next  pointer in the host controller  endpoint
		 * descriptor must contain an iommu address. Calculate
		 * the offset into the cpu address and add this to the
		 * starting iommu address.
		 */
		addr = ohci_ed_cpu_to_iommu(ohcip, (ohci_ed_t *)&list_array[i]);

		Set_ED(list_array[2*i + 1].hced_next, addr);
		Set_ED(list_array[2*i + 2].hced_next, addr);
	}

	/*
	 * Initialize the interrupt list in the HCCA so that it points
	 * to the bottom of the tree.
	 */
	for (i = 0; i < half_list; i++) {
		addr = ohci_ed_cpu_to_iommu(ohcip,
		    (ohci_ed_t *)&list_array[half_list - 1 + ohci_index[i]]);

		ASSERT(Get_ED(list_array[half_list - 1 +
		    ohci_index[i]].hced_ctrl));

		ASSERT(addr != 0);

		Set_HCCA(hccap->HccaIntTble[i], addr);
		Set_HCCA(hccap->HccaIntTble[i + half_list], addr);
	}
}


/*
 * ohci_take_control:
 *
 * Take control of the host controller. OpenHCI allows for optional support
 * of legacy devices through the use of System Management Mode software and
 * system Management interrupt hardware. See section 5.1.1.3 of the OpenHCI
 * spec for more details.
 */
static int
ohci_take_control(ohci_state_t	*ohcip)
{
#if defined(__x86)
	uint32_t hcr_control_val;
	uint32_t hcr_cmd_status_val;
	int wait;
#endif	/* __x86 */

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_take_control:");

#if defined(__x86)
	/*
	 * On x86, we must tell the BIOS we want the controller,
	 * and wait for it to respond that we can have it.
	 */
	hcr_control_val = Get_OpReg(hcr_control);
	if ((hcr_control_val & HCR_CONTROL_IR) == 0) {
		USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_take_control: InterruptRouting off\n");

		return (DDI_SUCCESS);
	}

	/* attempt the OwnershipChange request */
	hcr_cmd_status_val = Get_OpReg(hcr_cmd_status);
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_take_control: hcr_cmd_status: 0x%x\n",
	    hcr_cmd_status_val);
	hcr_cmd_status_val |= HCR_STATUS_OCR;

	Set_OpReg(hcr_cmd_status, hcr_cmd_status_val);


	mutex_exit(&ohcip->ohci_int_mutex);
	/* now wait for 5 seconds for InterruptRouting to go away */
	for (wait = 0; wait < 5000; wait++) {
		if ((Get_OpReg(hcr_control) & HCR_CONTROL_IR) == 0)
			break;
		delay(drv_usectohz(1000));
	}
	mutex_enter(&ohcip->ohci_int_mutex);

	if (wait >= 5000) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_take_control: couldn't take control from BIOS\n");

		return (DDI_FAILURE);
	}
#else	/* __x86 */
	/*
	 * On Sparc, there won't be  special System Management Mode
	 * hardware for legacy devices, while the x86 platforms may
	 * have to deal with  this. This  function may be  platform
	 * specific.
	 *
	 * The interrupt routing bit should not be set.
	 */
	if (Get_OpReg(hcr_control) & HCR_CONTROL_IR) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_take_control: Routing bit set");

		return (DDI_FAILURE);
	}
#endif	/* __x86 */

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_take_control: End");

	return (DDI_SUCCESS);
}

/*
 * ohci_pm_support:
 *	always return success since PM has been quite reliable on ohci
 */
/*ARGSUSED*/
int
ohci_hcdi_pm_support(dev_info_t *dip)
{
	return (USB_SUCCESS);
}

/*
 * ohci_alloc_hcdi_ops:
 *
 * The HCDI interfaces or entry points are the software interfaces used by
 * the Universal Serial Bus Driver  (USBA) to  access the services of the
 * Host Controller Driver (HCD).  During HCD initialization, inform  USBA
 * about all available HCDI interfaces or entry points.
 */
static usba_hcdi_ops_t *
ohci_alloc_hcdi_ops(ohci_state_t	*ohcip)
{
	usba_hcdi_ops_t			*usba_hcdi_ops;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_alloc_hcdi_ops:");

	usba_hcdi_ops = usba_alloc_hcdi_ops();

	usba_hcdi_ops->usba_hcdi_ops_version = HCDI_OPS_VERSION;

	usba_hcdi_ops->usba_hcdi_pm_support = ohci_hcdi_pm_support;
	usba_hcdi_ops->usba_hcdi_pipe_open = ohci_hcdi_pipe_open;
	usba_hcdi_ops->usba_hcdi_pipe_close = ohci_hcdi_pipe_close;

	usba_hcdi_ops->usba_hcdi_pipe_reset = ohci_hcdi_pipe_reset;
	usba_hcdi_ops->usba_hcdi_pipe_reset_data_toggle =
	    ohci_hcdi_pipe_reset_data_toggle;

	usba_hcdi_ops->usba_hcdi_pipe_ctrl_xfer = ohci_hcdi_pipe_ctrl_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_bulk_xfer = ohci_hcdi_pipe_bulk_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_intr_xfer = ohci_hcdi_pipe_intr_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_isoc_xfer = ohci_hcdi_pipe_isoc_xfer;

	usba_hcdi_ops->usba_hcdi_bulk_transfer_size =
	    ohci_hcdi_bulk_transfer_size;

	usba_hcdi_ops->usba_hcdi_pipe_stop_intr_polling =
	    ohci_hcdi_pipe_stop_intr_polling;
	usba_hcdi_ops->usba_hcdi_pipe_stop_isoc_polling =
	    ohci_hcdi_pipe_stop_isoc_polling;

	usba_hcdi_ops->usba_hcdi_get_current_frame_number =
	    ohci_hcdi_get_current_frame_number;
	usba_hcdi_ops->usba_hcdi_get_max_isoc_pkts =
	    ohci_hcdi_get_max_isoc_pkts;
	usba_hcdi_ops->usba_hcdi_console_input_init =
	    ohci_hcdi_polled_input_init;
	usba_hcdi_ops->usba_hcdi_console_input_enter =
	    ohci_hcdi_polled_input_enter;
	usba_hcdi_ops->usba_hcdi_console_read = ohci_hcdi_polled_read;
	usba_hcdi_ops->usba_hcdi_console_input_exit =
	    ohci_hcdi_polled_input_exit;
	usba_hcdi_ops->usba_hcdi_console_input_fini =
	    ohci_hcdi_polled_input_fini;

	usba_hcdi_ops->usba_hcdi_console_output_init =
	    ohci_hcdi_polled_output_init;
	usba_hcdi_ops->usba_hcdi_console_output_enter =
	    ohci_hcdi_polled_output_enter;
	usba_hcdi_ops->usba_hcdi_console_write = ohci_hcdi_polled_write;
	usba_hcdi_ops->usba_hcdi_console_output_exit =
	    ohci_hcdi_polled_output_exit;
	usba_hcdi_ops->usba_hcdi_console_output_fini =
	    ohci_hcdi_polled_output_fini;

	return (usba_hcdi_ops);
}


/*
 * Host Controller Driver (HCD) deinitialization functions
 */

/*
 * ohci_cleanup:
 *
 * Cleanup on attach failure or detach
 */
static int
ohci_cleanup(ohci_state_t	*ohcip)
{
	ohci_trans_wrapper_t	*tw;
	ohci_pipe_private_t	*pp;
	ohci_td_t		*td;
	int			i, state, rval;
	int			flags = ohcip->ohci_flags;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl, "ohci_cleanup:");

	if (flags & OHCI_RHREG) {
		/* Unload the root hub driver */
		if (ohci_unload_root_hub_driver(ohcip) != USB_SUCCESS) {

			return (DDI_FAILURE);
		}
	}

	if (flags & OHCI_USBAREG) {
		/* Unregister this HCD instance with USBA */
		usba_hcdi_unregister(ohcip->ohci_dip);
	}

	if (flags & OHCI_INTR) {

		mutex_enter(&ohcip->ohci_int_mutex);

		/* Disable all HC ED list processing */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) & ~(HCR_CONTROL_CLE |
		    HCR_CONTROL_BLE | HCR_CONTROL_PLE | HCR_CONTROL_IE)));

		/* Disable all HC interrupts */
		Set_OpReg(hcr_intr_disable,
		    (HCR_INTR_SO | HCR_INTR_WDH | HCR_INTR_RD | HCR_INTR_UE));

		/* Wait for the next SOF */
		(void) ohci_wait_for_sof(ohcip);

		/* Disable Master and SOF interrupts */
		Set_OpReg(hcr_intr_disable, (HCR_INTR_MIE | HCR_INTR_SOF));

		/* Set the Host Controller Functional State to Reset */
		Set_OpReg(hcr_control, ((Get_OpReg(hcr_control) &
		    (~HCR_CONTROL_HCFS)) | HCR_CONTROL_RESET));

		mutex_exit(&ohcip->ohci_int_mutex);
		/* Wait for sometime */
		delay(drv_usectohz(OHCI_TIMEWAIT));
		mutex_enter(&ohcip->ohci_int_mutex);

		/*
		 * Workaround for ULI1575 chipset. Following OHCI Operational
		 * Memory Registers are not cleared to their default value
		 * on reset. Explicitly set the registers to default value.
		 */
		if (ohcip->ohci_vendor_id == PCI_ULI1575_VENID &&
		    ohcip->ohci_device_id == PCI_ULI1575_DEVID) {
			Set_OpReg(hcr_control, HCR_CONTROL_DEFAULT);
			Set_OpReg(hcr_intr_enable, HCR_INT_ENABLE_DEFAULT);
			Set_OpReg(hcr_HCCA, HCR_HCCA_DEFAULT);
			Set_OpReg(hcr_ctrl_head, HCR_CONTROL_HEAD_ED_DEFAULT);
			Set_OpReg(hcr_bulk_head, HCR_BULK_HEAD_ED_DEFAULT);
			Set_OpReg(hcr_frame_interval,
			    HCR_FRAME_INTERVAL_DEFAULT);
			Set_OpReg(hcr_periodic_strt,
			    HCR_PERIODIC_START_DEFAULT);
		}

		mutex_exit(&ohcip->ohci_int_mutex);

		ohci_rem_intrs(ohcip);
	}

	/* Unmap the OHCI registers */
	if (ohcip->ohci_regs_handle) {
		/* Reset the host controller */
		Set_OpReg(hcr_cmd_status, HCR_STATUS_RESET);

		ddi_regs_map_free(&ohcip->ohci_regs_handle);
	}

	if (ohcip->ohci_config_handle) {
		pci_config_teardown(&ohcip->ohci_config_handle);
	}

	/* Free all the buffers */
	if (ohcip->ohci_td_pool_addr && ohcip->ohci_td_pool_mem_handle) {
		for (i = 0; i < ohci_td_pool_size; i ++) {
			td = &ohcip->ohci_td_pool_addr[i];
			state = Get_TD(ohcip->ohci_td_pool_addr[i].hctd_state);

			if ((state != HC_TD_FREE) && (state != HC_TD_DUMMY) &&
			    (td->hctd_trans_wrapper)) {

				mutex_enter(&ohcip->ohci_int_mutex);

				tw = (ohci_trans_wrapper_t *)
				    OHCI_LOOKUP_ID((uint32_t)
				    Get_TD(td->hctd_trans_wrapper));

				/* Obtain the pipe private structure */
				pp = tw->tw_pipe_private;

				/* Stop the the transfer timer */
				ohci_stop_xfer_timer(ohcip, tw,
				    OHCI_REMOVE_XFER_ALWAYS);

				ohci_deallocate_tw_resources(ohcip, pp, tw);

				mutex_exit(&ohcip->ohci_int_mutex);
			}
		}

		/*
		 * If OHCI_TD_POOL_BOUND flag is set, then unbind
		 * the handle for TD pools.
		 */
		if ((ohcip->ohci_dma_addr_bind_flag &
		    OHCI_TD_POOL_BOUND) == OHCI_TD_POOL_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ohcip->ohci_td_pool_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}
		ddi_dma_mem_free(&ohcip->ohci_td_pool_mem_handle);
	}

	/* Free the TD pool */
	if (ohcip->ohci_td_pool_dma_handle) {
		ddi_dma_free_handle(&ohcip->ohci_td_pool_dma_handle);
	}

	if (ohcip->ohci_ed_pool_addr && ohcip->ohci_ed_pool_mem_handle) {
		/*
		 * If OHCI_ED_POOL_BOUND flag is set, then unbind
		 * the handle for ED pools.
		 */
		if ((ohcip->ohci_dma_addr_bind_flag &
		    OHCI_ED_POOL_BOUND) == OHCI_ED_POOL_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ohcip->ohci_ed_pool_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}

		ddi_dma_mem_free(&ohcip->ohci_ed_pool_mem_handle);
	}

	/* Free the ED pool */
	if (ohcip->ohci_ed_pool_dma_handle) {
		ddi_dma_free_handle(&ohcip->ohci_ed_pool_dma_handle);
	}

	/* Free the HCCA area */
	if (ohcip->ohci_hccap && ohcip->ohci_hcca_mem_handle) {
		/*
		 * If OHCI_HCCA_DMA_BOUND flag is set, then unbind
		 * the handle for HCCA.
		 */
		if ((ohcip->ohci_dma_addr_bind_flag &
		    OHCI_HCCA_DMA_BOUND) == OHCI_HCCA_DMA_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ohcip->ohci_hcca_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}

		ddi_dma_mem_free(&ohcip->ohci_hcca_mem_handle);
	}

	if (ohcip->ohci_hcca_dma_handle) {
		ddi_dma_free_handle(&ohcip->ohci_hcca_dma_handle);
	}

	if (flags & OHCI_INTR) {

		/* Destroy the mutex */
		mutex_destroy(&ohcip->ohci_int_mutex);

		/* Destroy the SOF condition varibale */
		cv_destroy(&ohcip->ohci_SOF_cv);

		/* Destroy the serialize opens and closes semaphore */
		sema_destroy(&ohcip->ohci_ocsem);
	}

	/* clean up kstat structs */
	ohci_destroy_stats(ohcip);

	/* Free ohci hcdi ops */
	if (ohcip->ohci_hcdi_ops) {
		usba_free_hcdi_ops(ohcip->ohci_hcdi_ops);
	}

	if (flags & OHCI_ZALLOC) {

		usb_free_log_hdl(ohcip->ohci_log_hdl);

		/* Remove all properties that might have been created */
		ddi_prop_remove_all(ohcip->ohci_dip);

		/* Free the soft state */
		ddi_soft_state_free(ohci_statep,
		    ddi_get_instance(ohcip->ohci_dip));
	}

	return (DDI_SUCCESS);
}


/*
 * ohci_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
ohci_rem_intrs(ohci_state_t	*ohcip)
{
	int	i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_rem_intrs: interrupt type 0x%x", ohcip->ohci_intr_type);

	/* Disable all interrupts */
	if (ohcip->ohci_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(ohcip->ohci_htable,
		    ohcip->ohci_intr_cnt);
	} else {
		for (i = 0; i < ohcip->ohci_intr_cnt; i++) {
			(void) ddi_intr_disable(ohcip->ohci_htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < ohcip->ohci_intr_cnt; i++) {
		(void) ddi_intr_remove_handler(ohcip->ohci_htable[i]);
		(void) ddi_intr_free(ohcip->ohci_htable[i]);
	}

	kmem_free(ohcip->ohci_htable,
	    ohcip->ohci_intr_cnt * sizeof (ddi_intr_handle_t));
}


/*
 * ohci_cpr_suspend
 */
static int
ohci_cpr_suspend(ohci_state_t	*ohcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_cpr_suspend:");

	/* Call into the root hub and suspend it */
	if (usba_hubdi_detach(ohcip->ohci_dip, DDI_SUSPEND) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	/* Only root hub's intr pipe should be open at this time */
	mutex_enter(&ohcip->ohci_int_mutex);

	if (ohcip->ohci_open_pipe_count > 1) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_cpr_suspend: fails as open pipe count = %d",
		    ohcip->ohci_open_pipe_count);

		mutex_exit(&ohcip->ohci_int_mutex);

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_cpr_suspend: Disable HC ED list processing");

	/* Disable all HC ED list processing */
	Set_OpReg(hcr_control, (Get_OpReg(hcr_control) & ~(HCR_CONTROL_CLE |
	    HCR_CONTROL_BLE | HCR_CONTROL_PLE | HCR_CONTROL_IE)));

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_cpr_suspend: Disable HC interrupts");

	/* Disable all HC interrupts */
	Set_OpReg(hcr_intr_disable, ~(HCR_INTR_MIE|HCR_INTR_SOF));

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_cpr_suspend: Wait for the next SOF");

	/* Wait for the next SOF */
	if (ohci_wait_for_sof(ohcip) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_cpr_suspend: ohci host controller suspend failed");

		mutex_exit(&ohcip->ohci_int_mutex);
		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_cpr_suspend: Disable Master interrupt");

	/*
	 * Disable Master interrupt so that ohci driver don't
	 * get any ohci interrupts.
	 */
	Set_OpReg(hcr_intr_disable, HCR_INTR_MIE);

	/*
	 * Suspend the ohci host controller
	 * if usb keyboard is not connected.
	 */
	if (ohcip->ohci_polled_kbd_count == 0 || force_ohci_off != 0) {
		Set_OpReg(hcr_control, HCR_CONTROL_SUSPD);
	}

	/* Set host controller soft state to suspend */
	ohcip->ohci_hc_soft_state = OHCI_CTLR_SUSPEND_STATE;

	mutex_exit(&ohcip->ohci_int_mutex);

	return (DDI_SUCCESS);
}


/*
 * ohci_cpr_resume
 */
static int
ohci_cpr_resume(ohci_state_t	*ohcip)
{
	mutex_enter(&ohcip->ohci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "ohci_cpr_resume: Restart the controller");

	/* Cleanup ohci specific information across cpr */
	ohci_cpr_cleanup(ohcip);

	/* Restart the controller */
	if (ohci_init_ctlr(ohcip) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "ohci_cpr_resume: ohci host controller resume failed ");

		mutex_exit(&ohcip->ohci_int_mutex);

		return (DDI_FAILURE);
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	/* Now resume the root hub */
	if (usba_hubdi_attach(ohcip->ohci_dip, DDI_RESUME) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * HCDI entry points
 *
 * The Host Controller Driver Interfaces (HCDI) are the software interfaces
 * between the Universal Serial Bus Layer (USBA) and the Host Controller
 * Driver (HCD). The HCDI interfaces or entry points are subject to change.
 */

/*
 * ohci_hcdi_pipe_open:
 *
 * Member of HCD Ops structure and called during client specific pipe open
 * Add the pipe to the data structure representing the device and allocate
 * bandwidth for the pipe if it is a interrupt or isochronous endpoint.
 */
static int
ohci_hcdi_pipe_open(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*epdt = &ph->p_ep;
	int			rval, error = USB_SUCCESS;
	int			kmflag = (flags & USB_FLAGS_SLEEP) ?
	    KM_SLEEP : KM_NOSLEEP;
	uint_t			node = 0;
	ohci_pipe_private_t	*pp;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_open: addr = 0x%x, ep%d",
	    ph->p_usba_device->usb_addr,
	    epdt->bEndpointAddress & USB_EP_NUM_MASK);

	sema_p(&ohcip->ohci_ocsem);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);
	mutex_exit(&ohcip->ohci_int_mutex);

	if (rval != USB_SUCCESS) {
		sema_v(&ohcip->ohci_ocsem);

		return (rval);
	}

	/*
	 * Check and handle root hub pipe open.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		mutex_enter(&ohcip->ohci_int_mutex);
		error = ohci_handle_root_hub_pipe_open(ph, flags);
		mutex_exit(&ohcip->ohci_int_mutex);
		sema_v(&ohcip->ohci_ocsem);

		return (error);
	}

	/*
	 * Opening of other pipes excluding root hub pipe are
	 * handled below. Check whether pipe is already opened.
	 */
	if (ph->p_hcd_private) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
		    "ohci_hcdi_pipe_open: Pipe is already opened");

		sema_v(&ohcip->ohci_ocsem);

		return (USB_FAILURE);
	}

	/*
	 * A portion of the bandwidth is reserved for the non-periodic
	 * transfers, i.e control and bulk transfers in each of one
	 * millisecond frame period & usually it will be 10% of frame
	 * period. Hence there is no need to check for the available
	 * bandwidth before adding the control or bulk endpoints.
	 *
	 * There is a need to check for the available bandwidth before
	 * adding the periodic transfers, i.e interrupt & isochronous,
	 * since all these periodic transfers are guaranteed transfers.
	 * Usually 90% of the total frame time is reserved for periodic
	 * transfers.
	 */
	if (OHCI_PERIODIC_ENDPOINT(epdt)) {

		mutex_enter(&ohcip->ohci_int_mutex);
		mutex_enter(&ph->p_mutex);

		error = ohci_allocate_bandwidth(ohcip, ph, &node);

		if (error != USB_SUCCESS) {

			USB_DPRINTF_L2(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
			    "ohci_hcdi_pipe_open: Bandwidth allocation failed");

			mutex_exit(&ph->p_mutex);
			mutex_exit(&ohcip->ohci_int_mutex);
			sema_v(&ohcip->ohci_ocsem);

			return (error);
		}

		mutex_exit(&ph->p_mutex);
		mutex_exit(&ohcip->ohci_int_mutex);
	}

	/* Create the HCD pipe private structure */
	pp = kmem_zalloc(sizeof (ohci_pipe_private_t), kmflag);

	/*
	 * Return failure if ohci pipe private
	 * structure allocation fails.
	 */
	if (pp == NULL) {

		mutex_enter(&ohcip->ohci_int_mutex);

		/* Deallocate bandwidth */
		if (OHCI_PERIODIC_ENDPOINT(epdt)) {

			mutex_enter(&ph->p_mutex);
			ohci_deallocate_bandwidth(ohcip, ph);
			mutex_exit(&ph->p_mutex);
		}

		mutex_exit(&ohcip->ohci_int_mutex);
		sema_v(&ohcip->ohci_ocsem);

		return (USB_NO_RESOURCES);
	}

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Store the node in the interrupt lattice */
	pp->pp_node = node;

	/* Create prototype for xfer completion condition variable */
	cv_init(&pp->pp_xfer_cmpl_cv, NULL, CV_DRIVER, NULL);

	/* Set the state of pipe as idle */
	pp->pp_state = OHCI_PIPE_STATE_IDLE;

	/* Store a pointer to the pipe handle */
	pp->pp_pipe_handle = ph;

	mutex_enter(&ph->p_mutex);

	/* Store the pointer in the pipe handle */
	ph->p_hcd_private = (usb_opaque_t)pp;

	/* Store a copy of the pipe policy */
	bcopy(&ph->p_policy, &pp->pp_policy, sizeof (usb_pipe_policy_t));

	mutex_exit(&ph->p_mutex);

	/* Allocate the host controller endpoint descriptor */
	pp->pp_ept = ohci_alloc_hc_ed(ohcip, ph);

	if (pp->pp_ept == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
		    "ohci_hcdi_pipe_open: ED allocation failed");

		mutex_enter(&ph->p_mutex);

		/* Deallocate bandwidth */
		if (OHCI_PERIODIC_ENDPOINT(epdt)) {

			ohci_deallocate_bandwidth(ohcip, ph);
		}

		/* Destroy the xfer completion condition varibale */
		cv_destroy(&pp->pp_xfer_cmpl_cv);

		/*
		 * Deallocate the hcd private portion
		 * of the pipe handle.
		 */
		kmem_free(ph->p_hcd_private, sizeof (ohci_pipe_private_t));

		/*
		 * Set the private structure in the
		 * pipe handle equal to NULL.
		 */
		ph->p_hcd_private = NULL;
		mutex_exit(&ph->p_mutex);

		mutex_exit(&ohcip->ohci_int_mutex);
		sema_v(&ohcip->ohci_ocsem);

		return (USB_NO_RESOURCES);
	}

	/* Restore the data toggle information */
	ohci_restore_data_toggle(ohcip, ph);

	/*
	 * Insert the endpoint onto the host controller's
	 * appropriate endpoint list. The host controller
	 * will not schedule this endpoint and will not have
	 * any TD's to process.
	 */
	ohci_insert_ed(ohcip, ph);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_open: ph = 0x%p", (void *)ph);

	ohcip->ohci_open_pipe_count++;

	mutex_exit(&ohcip->ohci_int_mutex);

	sema_v(&ohcip->ohci_ocsem);

	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_pipe_close:
 *
 * Member of HCD Ops structure and called during the client  specific pipe
 * close. Remove the pipe and the data structure representing the device.
 * Deallocate  bandwidth for the pipe if it is a interrupt or isochronous
 * endpoint.
 */
/* ARGSUSED */
static int
ohci_hcdi_pipe_close(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_close: addr = 0x%x, ep%d",
	    ph->p_usba_device->usb_addr,
	    eptd->bEndpointAddress & USB_EP_NUM_MASK);

	sema_p(&ohcip->ohci_ocsem);

	/* Check and handle root hub pipe close */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		mutex_enter(&ohcip->ohci_int_mutex);
		error = ohci_handle_root_hub_pipe_close(ph);
		mutex_exit(&ohcip->ohci_int_mutex);
		sema_v(&ohcip->ohci_ocsem);

		return (error);
	}

	ASSERT(ph->p_hcd_private != NULL);

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Set pipe state to pipe close */
	pp->pp_state = OHCI_PIPE_STATE_CLOSE;

	ohci_pipe_cleanup(ohcip, ph);

	/*
	 * Remove the endoint descriptor from Host
	 * Controller's appropriate endpoint list.
	 */
	ohci_remove_ed(ohcip, pp);

	/* Deallocate bandwidth */
	if (OHCI_PERIODIC_ENDPOINT(eptd)) {

		mutex_enter(&ph->p_mutex);
		ohci_deallocate_bandwidth(ohcip, ph);
		mutex_exit(&ph->p_mutex);
	}

	mutex_enter(&ph->p_mutex);

	/* Destroy the xfer completion condition varibale */
	cv_destroy(&pp->pp_xfer_cmpl_cv);

	/*
	 * Deallocate the hcd private portion
	 * of the pipe handle.
	 */
	kmem_free(ph->p_hcd_private, sizeof (ohci_pipe_private_t));
	ph->p_hcd_private = NULL;

	mutex_exit(&ph->p_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_close: ph = 0x%p", (void *)ph);

	ohcip->ohci_open_pipe_count--;

	mutex_exit(&ohcip->ohci_int_mutex);
	sema_v(&ohcip->ohci_ocsem);

	return (error);
}


/*
 * ohci_hcdi_pipe_reset:
 */
/* ARGSUSED */
static int
ohci_hcdi_pipe_reset(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_reset: ph = 0x%p ", (void *)ph);

	/*
	 * Check and handle root hub pipe reset.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		error = ohci_handle_root_hub_pipe_reset(ph, usb_flags);
		return (error);
	}

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Set pipe state to pipe reset */
	pp->pp_state = OHCI_PIPE_STATE_RESET;

	ohci_pipe_cleanup(ohcip, ph);

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}

/*
 * ohci_hcdi_pipe_reset_data_toggle:
 */
void
ohci_hcdi_pipe_reset_data_toggle(
	usba_pipe_handle_data_t	*ph)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_reset_data_toggle:");

	mutex_enter(&ohcip->ohci_int_mutex);

	mutex_enter(&ph->p_mutex);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    DATA0);
	mutex_exit(&ph->p_mutex);

	Set_ED(pp->pp_ept->hced_headp,
	    Get_ED(pp->pp_ept->hced_headp) & (~HC_EPT_Carry));
	mutex_exit(&ohcip->ohci_int_mutex);

}

/*
 * ohci_hcdi_pipe_ctrl_xfer:
 */
static int
ohci_hcdi_pipe_ctrl_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	int			rval;
	int			error = USB_SUCCESS;
	ohci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_ctrl_xfer: ph = 0x%p reqp = 0x%p flags = 0x%x",
	    (void *)ph, (void *)ctrl_reqp, usb_flags);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);
	mutex_exit(&ohcip->ohci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	/*
	 * Check and handle root hub control request.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		error = ohci_handle_root_hub_request(ohcip, ph, ctrl_reqp);

		return (error);
	}

	mutex_enter(&ohcip->ohci_int_mutex);

	/*
	 *  Check whether pipe is in halted state.
	 */
	if (pp->pp_state == OHCI_PIPE_STATE_ERROR) {

		USB_DPRINTF_L2(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
		    "ohci_hcdi_pipe_ctrl_xfer:"
		    "Pipe is in error state, need pipe reset to continue");

		mutex_exit(&ohcip->ohci_int_mutex);

		return (USB_FAILURE);
	}

	/* Allocate a transfer wrapper */
	if ((tw = ohci_allocate_ctrl_resources(ohcip, pp, ctrl_reqp,
	    usb_flags)) == NULL) {

		error = USB_NO_RESOURCES;
	} else {
		/* Insert the td's on the endpoint */
		ohci_insert_ctrl_req(ohcip, ph, ctrl_reqp, tw, usb_flags);
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}


/*
 * ohci_hcdi_bulk_transfer_size:
 *
 * Return maximum bulk transfer size
 */

/* ARGSUSED */
static int
ohci_hcdi_bulk_transfer_size(
	usba_device_t	*usba_device,
	size_t		*size)
{
	ohci_state_t	*ohcip = ohci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_bulk_transfer_size:");

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);
	mutex_exit(&ohcip->ohci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	*size = OHCI_MAX_BULK_XFER_SIZE;

	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_pipe_bulk_xfer:
 */
static int
ohci_hcdi_pipe_bulk_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_bulk_req_t		*bulk_reqp,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	int			rval, error = USB_SUCCESS;
	ohci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_bulk_xfer: ph = 0x%p reqp = 0x%p flags = 0x%x",
	    (void *)ph, (void *)bulk_reqp, usb_flags);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);

		return (rval);
	}

	/*
	 *  Check whether pipe is in halted state.
	 */
	if (pp->pp_state == OHCI_PIPE_STATE_ERROR) {

		USB_DPRINTF_L2(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
		    "ohci_hcdi_pipe_bulk_xfer:"
		    "Pipe is in error state, need pipe reset to continue");

		mutex_exit(&ohcip->ohci_int_mutex);

		return (USB_FAILURE);
	}

	/* Allocate a transfer wrapper */
	if ((tw = ohci_allocate_bulk_resources(ohcip, pp, bulk_reqp,
	    usb_flags)) == NULL) {

		error = USB_NO_RESOURCES;
	} else {
		/* Add the TD into the Host Controller's bulk list */
		ohci_insert_bulk_req(ohcip, ph, bulk_reqp, tw, usb_flags);
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}


/*
 * ohci_hcdi_pipe_intr_xfer:
 */
static int
ohci_hcdi_pipe_intr_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*intr_reqp,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			pipe_dir, rval, error = USB_SUCCESS;
	ohci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_intr_xfer: ph = 0x%p reqp = 0x%p flags = 0x%x",
	    (void *)ph, (void *)intr_reqp, usb_flags);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);

		return (rval);
	}

	/* Get the pipe direction */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	if (pipe_dir == USB_EP_DIR_IN) {
		error = ohci_start_periodic_pipe_polling(ohcip, ph,
		    (usb_opaque_t)intr_reqp, usb_flags);
	} else {
		/* Allocate transaction resources */
		if ((tw = ohci_allocate_intr_resources(ohcip, ph,
		    intr_reqp, usb_flags)) == NULL) {
			error = USB_NO_RESOURCES;
		} else {
			ohci_insert_intr_req(ohcip,
			    (ohci_pipe_private_t *)ph->p_hcd_private,
			    tw, usb_flags);
		}
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}


/*
 * ohci_hcdi_pipe_stop_intr_polling()
 */
static int
ohci_hcdi_pipe_stop_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_stop_intr_polling: ph = 0x%p fl = 0x%x",
	    (void *)ph, flags);

	mutex_enter(&ohcip->ohci_int_mutex);

	error = ohci_stop_periodic_pipe_polling(ohcip, ph, flags);

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}


/*
 * ohci_hcdi_get_current_frame_number:
 *
 * Get the current usb frame number.
 * Return whether the request is handled successfully.
 */
static int
ohci_hcdi_get_current_frame_number(
	usba_device_t		*usba_device,
	usb_frame_number_t	*frame_number)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int			rval;

	ohcip = ohci_obtain_state(usba_device->usb_root_hub_dip);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);

		return (rval);
	}

	*frame_number = ohci_get_current_frame_number(ohcip);

	mutex_exit(&ohcip->ohci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_get_current_frame_number:"
	    "Current frame number 0x%llx", (unsigned long long)(*frame_number));

	return (rval);
}


/*
 * ohci_hcdi_get_max_isoc_pkts:
 *
 * Get maximum isochronous packets per usb isochronous request.
 * Return whether the request is handled successfully.
 */
static int
ohci_hcdi_get_max_isoc_pkts(
	usba_device_t	*usba_device,
	uint_t		*max_isoc_pkts_per_request)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int			rval;

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);
	mutex_exit(&ohcip->ohci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	*max_isoc_pkts_per_request = OHCI_MAX_ISOC_PKTS_PER_XFER;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_get_max_isoc_pkts: maximum isochronous"
	    "packets per usb isochronous request = 0x%x",
	    *max_isoc_pkts_per_request);

	return (rval);
}


/*
 * ohci_hcdi_pipe_isoc_xfer:
 */
static int
ohci_hcdi_pipe_isoc_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			error = USB_SUCCESS;
	int			pipe_dir, rval;
	ohci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_isoc_xfer: ph = 0x%p reqp = 0x%p flags = 0x%x",
	    (void *)ph, (void *)isoc_reqp, usb_flags);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);

		return (rval);
	}

	/* Get the isochronous pipe direction */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_isoc_xfer: isoc_reqp = 0x%p, uf = 0x%x",
	    (void *)isoc_reqp, usb_flags);

	if (pipe_dir == USB_EP_DIR_IN) {
		error = ohci_start_periodic_pipe_polling(ohcip, ph,
		    (usb_opaque_t)isoc_reqp, usb_flags);
	} else {
		/* Allocate transaction resources */
		if ((tw = ohci_allocate_isoc_resources(ohcip, ph,
		    isoc_reqp, usb_flags)) == NULL) {
			error = USB_NO_RESOURCES;
		} else {
			error = ohci_insert_isoc_req(ohcip,
			    (ohci_pipe_private_t *)ph->p_hcd_private,
			    tw, usb_flags);
		}
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}


/*
 * ohci_hcdi_pipe_stop_isoc_polling()
 */
static int
ohci_hcdi_pipe_stop_isoc_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			rval, error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ohcip->ohci_log_hdl,
	    "ohci_hcdi_pipe_stop_isoc_polling: ph = 0x%p fl = 0x%x",
	    (void *)ph, flags);

	mutex_enter(&ohcip->ohci_int_mutex);
	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ohcip->ohci_int_mutex);
		return (rval);
	}

	error = ohci_stop_periodic_pipe_polling(ohcip, ph, flags);

	mutex_exit(&ohcip->ohci_int_mutex);
	return (error);
}


/*
 * Bandwidth Allocation functions
 */

/*
 * ohci_allocate_bandwidth:
 *
 * Figure out whether or not this interval may be supported. Return the index
 * into the  lattice if it can be supported.  Return allocation failure if it
 * can not be supported.
 *
 * The lattice structure looks like this with the bottom leaf actually
 * being an array.  There is a total of 63 nodes in this tree.	The lattice tree
 * itself is 0 based, while the bottom leaf array is 0 based.  The 0 bucket in
 * the bottom leaf array is used to store the smalled allocated bandwidth of all
 * the leaves.
 *
 *	0
 *    1   2
 *   3 4 5 6
 *   ...
 *  (32 33 ... 62 63)	  <-- last row does not exist in lattice, but an array
 *   0 1 2 3 ... 30 31
 *
 * We keep track of the bandwidth that each leaf uses.	First we search for the
 * first leaf with the smallest used bandwidth.  Based on that leaf we find the
 * parent node of that leaf based on the interval time.
 *
 * From the parent node, we find all the leafs of that subtree and update the
 * additional bandwidth needed.  In order to balance the load the leaves are not
 * executed directly from left to right, but scattered.  For a better picture
 * refer to Section 3.3.2 in the OpenHCI 1.0 spec, there should be a figure
 * showing the Interrupt ED Structure.
 */
static int
ohci_allocate_bandwidth(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			*node)
{
	int			interval, error, i;
	uint_t			min, min_index, height;
	uint_t			leftmost, list, bandwidth;
	usb_ep_descr_t		*endpoint = &ph->p_ep;

	/* This routine is protected by the ohci_int_mutex */
	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Calculate the length in bytes of a transaction on this
	 * periodic endpoint.
	 */
	mutex_enter(&ph->p_usba_device->usb_mutex);
	error = ohci_compute_total_bandwidth(
	    endpoint, ph->p_usba_device->usb_port_status, &bandwidth);
	mutex_exit(&ph->p_usba_device->usb_mutex);

	/*
	 * If length is zero, then, it means endpoint maximum packet
	 * supported is zero.  In that case, return failure without
	 * allocating any bandwidth.
	 */
	if (error != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_BW, ohcip->ohci_log_hdl,
		    "ohci_allocate_bandwidth: Periodic endpoint with "
		    "zero endpoint maximum packet size is not supported");

		return (USB_NOT_SUPPORTED);
	}

	/*
	 * If the length in bytes plus the allocated bandwidth exceeds
	 * the maximum, return bandwidth allocation failure.
	 */
	if ((ohcip->ohci_periodic_minimum_bandwidth + bandwidth) >
	    (MAX_PERIODIC_BANDWIDTH)) {

		USB_DPRINTF_L2(PRINT_MASK_BW, ohcip->ohci_log_hdl,
		    "ohci_allocate_bandwidth: Reached maximum "
		    "bandwidth value and cannot allocate bandwidth "
		    "for a given periodic endpoint");

		return (USB_NO_BANDWIDTH);
	}

	/* Adjust polling interval to be a power of 2 */
	mutex_enter(&ph->p_usba_device->usb_mutex);
	interval = ohci_adjust_polling_interval(ohcip,
	    endpoint, ph->p_usba_device->usb_port_status);
	mutex_exit(&ph->p_usba_device->usb_mutex);

	/*
	 * If this interval can't be supported,
	 * return allocation failure.
	 */
	if (interval == USB_FAILURE) {

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_BW, ohcip->ohci_log_hdl,
	    "The new interval is %d", interval);

	/* Find the leaf with the smallest allocated bandwidth */
	min_index = 0;
	min = ohcip->ohci_periodic_bandwidth[0];

	for (i = 1; i < NUM_INTR_ED_LISTS; i++) {
		if (ohcip->ohci_periodic_bandwidth[i] < min) {
			min_index = i;
			min = ohcip->ohci_periodic_bandwidth[i];
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_BW, ohcip->ohci_log_hdl,
	    "The leaf %d for minimal bandwidth %d", min_index, min);

	/* Adjust min for the lattice */
	min_index = min_index + NUM_INTR_ED_LISTS - 1;

	/*
	 * Find the index into the lattice given the
	 * leaf with the smallest allocated bandwidth.
	 */
	height = ohci_lattice_height(interval);

	USB_DPRINTF_L4(PRINT_MASK_BW, ohcip->ohci_log_hdl,
	    "The height is %d", height);

	*node = min_index;

	for (i = 0; i < height; i++) {
		*node = ohci_lattice_parent(*node);
	}

	USB_DPRINTF_L4(PRINT_MASK_BW, ohcip->ohci_log_hdl,
	    "Real node is %d", *node);

	/*
	 * Find the leftmost leaf in the subtree
	 * specified by the node.
	 */
	leftmost = ohci_leftmost_leaf(*node, height);

	USB_DPRINTF_L4(PRINT_MASK_BW, ohcip->ohci_log_hdl,
	    "Leftmost %d", leftmost);

	for (i = 0; i < (NUM_INTR_ED_LISTS/interval); i++) {
		list = ohci_hcca_leaf_index(leftmost + i);
		if ((ohcip->ohci_periodic_bandwidth[list] +
		    bandwidth) > MAX_PERIODIC_BANDWIDTH) {

			USB_DPRINTF_L2(PRINT_MASK_BW, ohcip->ohci_log_hdl,
			    "ohci_allocate_bandwidth: Reached maximum "
			    "bandwidth value and cannot allocate bandwidth "
			    "for periodic endpoint");

			return (USB_NO_BANDWIDTH);
		}
	}

	/*
	 * All the leaves for this node must be updated with the bandwidth.
	 */
	for (i = 0; i < (NUM_INTR_ED_LISTS/interval); i++) {
		list = ohci_hcca_leaf_index(leftmost + i);
		ohcip->ohci_periodic_bandwidth[list] += bandwidth;
	}

	/* Find the leaf with the smallest allocated bandwidth */
	min_index = 0;
	min = ohcip->ohci_periodic_bandwidth[0];

	for (i = 1; i < NUM_INTR_ED_LISTS; i++) {
		if (ohcip->ohci_periodic_bandwidth[i] < min) {
			min_index = i;
			min = ohcip->ohci_periodic_bandwidth[i];
		}
	}

	/* Save the minimum for later use */
	ohcip->ohci_periodic_minimum_bandwidth = min;

	return (USB_SUCCESS);
}


/*
 * ohci_deallocate_bandwidth:
 *
 * Deallocate bandwidth for the given node in the lattice and the length
 * of transfer.
 */
static void
ohci_deallocate_bandwidth(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	uint_t			min, node, bandwidth;
	uint_t			height, leftmost, list;
	int			i, interval;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;

	/* This routine is protected by the ohci_int_mutex */
	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Obtain the length */
	mutex_enter(&ph->p_usba_device->usb_mutex);
	(void) ohci_compute_total_bandwidth(
	    endpoint, ph->p_usba_device->usb_port_status, &bandwidth);
	mutex_exit(&ph->p_usba_device->usb_mutex);

	/* Obtain the node */
	node = pp->pp_node;

	/* Adjust polling interval to be a power of 2 */
	mutex_enter(&ph->p_usba_device->usb_mutex);
	interval = ohci_adjust_polling_interval(ohcip,
	    endpoint, ph->p_usba_device->usb_port_status);
	mutex_exit(&ph->p_usba_device->usb_mutex);

	/* Find the height in the tree */
	height = ohci_lattice_height(interval);

	/*
	 * Find the leftmost leaf in the subtree specified by the node
	 */
	leftmost = ohci_leftmost_leaf(node, height);

	/* Delete the bandwith from the appropriate lists */
	for (i = 0; i < (NUM_INTR_ED_LISTS/interval); i++) {
		list = ohci_hcca_leaf_index(leftmost + i);
		ohcip->ohci_periodic_bandwidth[list] -= bandwidth;
	}

	min = ohcip->ohci_periodic_bandwidth[0];

	/* Recompute the minimum */
	for (i = 1; i < NUM_INTR_ED_LISTS; i++) {
		if (ohcip->ohci_periodic_bandwidth[i] < min) {
			min = ohcip->ohci_periodic_bandwidth[i];
		}
	}

	/* Save the minimum for later use */
	ohcip->ohci_periodic_minimum_bandwidth = min;
}


/*
 * ohci_compute_total_bandwidth:
 *
 * Given a periodic endpoint (interrupt or isochronous) determine the total
 * bandwidth for one transaction. The OpenHCI host controller traverses the
 * endpoint descriptor lists on a first-come-first-serve basis. When the HC
 * services an endpoint, only a single transaction attempt is made. The  HC
 * moves to the next Endpoint Descriptor after the first transaction attempt
 * rather than finishing the entire Transfer Descriptor. Therefore, when  a
 * Transfer Descriptor is inserted into the lattice, we will only count the
 * number of bytes for one transaction.
 *
 * The following are the formulas used for  calculating bandwidth in  terms
 * bytes and it is for the single USB full speed and low speed	transaction
 * respectively. The protocol overheads will be different for each of  type
 * of USB transfer and all these formulas & protocol overheads are  derived
 * from the 5.9.3 section of USB Specification & with the help of Bandwidth
 * Analysis white paper which is posted on the USB  developer forum.
 *
 * Full-Speed:
 *		Protocol overhead  + ((MaxPacketSize * 7)/6 )  + Host_Delay
 *
 * Low-Speed:
 *		Protocol overhead  + Hub LS overhead +
 *		  (Low-Speed clock * ((MaxPacketSize * 7)/6 )) + Host_Delay
 */
static int
ohci_compute_total_bandwidth(
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

	/* Add Host Controller specific delay to required bandwidth */
	*bandwidth = HOST_CONTROLLER_DELAY;

	/* Add bit-stuffing overhead */
	maxpacketsize = (ushort_t)((maxpacketsize * 7) / 6);

	/* Low Speed interrupt transaction */
	if (port_status == USBA_LOW_SPEED_DEV) {
		/* Low Speed interrupt transaction */
		*bandwidth += (LOW_SPEED_PROTO_OVERHEAD +
		    HUB_LOW_SPEED_PROTO_OVERHEAD +
		    (LOW_SPEED_CLOCK * maxpacketsize));
	} else {
		/* Full Speed transaction */
		*bandwidth += maxpacketsize;

		if ((endpoint->bmAttributes &
		    USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) {
			/* Full Speed interrupt transaction */
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
	}

	return (USB_SUCCESS);
}


/*
 * ohci_adjust_polling_interval:
 */
static int
ohci_adjust_polling_interval(
	ohci_state_t		*ohcip,
	usb_ep_descr_t		*endpoint,
	usb_port_status_t	port_status)
{
	uint_t			interval;
	int			i = 0;

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
	if ((interval < MIN_POLL_INTERVAL) ||
	    (interval > MAX_POLL_INTERVAL)) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_adjust_polling_interval: "
		    "Endpoint's poll interval must be between %d and %d ms",
		    MIN_POLL_INTERVAL, MAX_POLL_INTERVAL);

		return (USB_FAILURE);
	}

	/*
	 * According USB Specifications, a  full-speed endpoint can
	 * specify a desired polling interval 1ms to 255ms and a low
	 * speed  endpoints are limited to  specifying only 10ms to
	 * 255ms. But some old keyboards & mice uses polling interval
	 * of 8ms. For compatibility  purpose, we are using polling
	 * interval between 8ms & 255ms for low speed endpoints. But
	 * ohci driver will reject the any low speed endpoints which
	 * request polling interval less than 8ms.
	 */
	if ((port_status == USBA_LOW_SPEED_DEV) &&
	    (interval < MIN_LOW_SPEED_POLL_INTERVAL)) {

		USB_DPRINTF_L2(PRINT_MASK_BW, ohcip->ohci_log_hdl,
		    "ohci_adjust_polling_interval: "
		    "Low speed endpoint's poll interval of %d ms "
		    "is below threshold.  Rounding up to %d ms",
		    interval, MIN_LOW_SPEED_POLL_INTERVAL);

		interval = MIN_LOW_SPEED_POLL_INTERVAL;
	}

	/*
	 * If polling interval is greater than 32ms,
	 * adjust polling interval equal to 32ms.
	 */
	if (interval > NUM_INTR_ED_LISTS) {
		interval = NUM_INTR_ED_LISTS;
	}

	/*
	 * Find the nearest power of 2 that'sless
	 * than interval.
	 */
	while ((ohci_pow_2(i)) <= interval) {
		i++;
	}

	return (ohci_pow_2((i - 1)));
}


/*
 * ohci_lattice_height:
 *
 * Given the requested bandwidth, find the height in the tree at which the
 * nodes for this bandwidth fall.  The height is measured as the number of
 * nodes from the leaf to the level specified by bandwidth The root of the
 * tree is at height TREE_HEIGHT.
 */
static uint_t
ohci_lattice_height(uint_t interval)
{
	return (TREE_HEIGHT - (ohci_log_2(interval)));
}


/*
 * ohci_lattice_parent:
 */
static uint_t
ohci_lattice_parent(uint_t node)
{
	if ((node % 2) == 0) {
		return ((node/2) - 1);
	} else {
		return ((node + 1)/2 - 1);
	}
}


/*
 * ohci_leftmost_leaf:
 *
 * Find the leftmost leaf in the subtree specified by the node. Height refers
 * to number of nodes from the bottom of the tree to the node,	including the
 * node.
 *
 * The formula for a zero based tree is:
 *     2^H * Node + 2^H - 1
 * The leaf of the tree is an array, convert the number for the array.
 *     Subtract the size of nodes not in the array
 *     2^H * Node + 2^H - 1 - (NUM_INTR_ED_LIST - 1) =
 *     2^H * Node + 2^H - NUM_INTR_ED_LIST =
 *     2^H * (Node + 1) - NUM_INTR_ED_LIST
 *	   0
 *	 1   2
 *	0 1 2 3
 */
static uint_t
ohci_leftmost_leaf(
	uint_t	node,
	uint_t	height)
{
	return ((ohci_pow_2(height) * (node + 1)) - NUM_INTR_ED_LISTS);
}

/*
 * ohci_hcca_intr_index:
 *
 * Given a node in the lattice, find the index for the hcca interrupt table
 */
static uint_t
ohci_hcca_intr_index(uint_t node)
{
	/*
	 * Adjust the node to the array representing
	 * the bottom of the tree.
	 */
	node = node - NUM_STATIC_NODES;

	if ((node % 2) == 0) {
		return (ohci_index[node / 2]);
	} else {
		return (ohci_index[node / 2] + (NUM_INTR_ED_LISTS / 2));
	}
}

/*
 * ohci_hcca_leaf_index:
 *
 * Given a node in the bottom leaf array of the lattice, find the index
 * for the hcca interrupt table
 */
static uint_t
ohci_hcca_leaf_index(uint_t leaf)
{
	if ((leaf % 2) == 0) {
		return (ohci_index[leaf / 2]);
	} else {
		return (ohci_index[leaf / 2] + (NUM_INTR_ED_LISTS / 2));
	}
}

/*
 * ohci_pow_2:
 *
 * Compute 2 to the power
 */
static uint_t
ohci_pow_2(uint_t x)
{
	if (x == 0) {
		return (1);
	} else {
		return (2 << (x - 1));
	}
}


/*
 * ohci_log_2:
 *
 * Compute log base 2 of x
 */
static uint_t
ohci_log_2(uint_t x)
{
	int i = 0;

	while (x != 1) {
		x = x >> 1;
		i++;
	}

	return (i);
}


/*
 * Endpoint Descriptor (ED) manipulations functions
 */

/*
 * ohci_alloc_hc_ed:
 * NOTE: This function is also called from POLLED MODE.
 *
 * Allocate an endpoint descriptor (ED)
 */
ohci_ed_t *
ohci_alloc_hc_ed(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	int			i, state;
	ohci_ed_t		*hc_ed;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_alloc_hc_ed: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * The first 31 endpoints in the Endpoint Descriptor (ED)
	 * buffer pool are reserved for building interrupt lattice
	 * tree. Search for a blank endpoint descriptor in the ED
	 * buffer pool.
	 */
	for (i = NUM_STATIC_NODES; i < ohci_ed_pool_size; i ++) {
		state = Get_ED(ohcip->ohci_ed_pool_addr[i].hced_state);

		if (state == HC_EPT_FREE) {
			break;
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_alloc_hc_ed: Allocated %d", i);

	if (i == ohci_ed_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
		    "ohci_alloc_hc_ed: ED exhausted");

		return (NULL);
	} else {

		hc_ed = &ohcip->ohci_ed_pool_addr[i];

		USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
		    "ohci_alloc_hc_ed: Allocated address 0x%p", (void *)hc_ed);

		ohci_print_ed(ohcip, hc_ed);

		/* Unpack the endpoint descriptor into a control field */
		if (ph) {
			if ((ohci_initialize_dummy(ohcip,
			    hc_ed)) == USB_NO_RESOURCES) {
				bzero((void *)hc_ed, sizeof (ohci_ed_t));
				Set_ED(hc_ed->hced_state, HC_EPT_FREE);
				return (NULL);
			}

			Set_ED(hc_ed->hced_prev, 0);
			Set_ED(hc_ed->hced_next, 0);

			/* Change ED's state Active */
			Set_ED(hc_ed->hced_state, HC_EPT_ACTIVE);

			Set_ED(hc_ed->hced_ctrl,
			    ohci_unpack_endpoint(ohcip, ph));
		} else {
			Set_ED(hc_ed->hced_ctrl, HC_EPT_sKip);

			/* Change ED's state Static */
			Set_ED(hc_ed->hced_state, HC_EPT_STATIC);
		}

		return (hc_ed);
	}
}


/*
 * ohci_unpack_endpoint:
 *
 * Unpack the information in the pipe handle and create the first byte
 * of the Host Controller's (HC) Endpoint Descriptor (ED).
 */
static uint_t
ohci_unpack_endpoint(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	uint_t			maxpacketsize, addr, ctrl = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_unpack_endpoint:");

	ctrl = ph->p_usba_device->usb_addr;

	addr = endpoint->bEndpointAddress;

	/* Assign the endpoint's address */
	ctrl = ctrl | ((addr & USB_EP_NUM_MASK) << HC_EPT_EP_SHFT);

	/*
	 * Assign the direction. If the endpoint is a control endpoint,
	 * the direction is assigned by the Transfer Descriptor (TD).
	 */
	if ((endpoint->bmAttributes &
	    USB_EP_ATTR_MASK) != USB_EP_ATTR_CONTROL) {
		if (addr & USB_EP_DIR_MASK) {
			/* The direction is IN */
			ctrl = ctrl | HC_EPT_DF_IN;
		} else {
			/* The direction is OUT */
			ctrl = ctrl | HC_EPT_DF_OUT;
		}
	}

	/* Assign the speed */
	mutex_enter(&ph->p_usba_device->usb_mutex);
	if (ph->p_usba_device->usb_port_status == USBA_LOW_SPEED_DEV) {
		ctrl = ctrl | HC_EPT_Speed;
	}
	mutex_exit(&ph->p_usba_device->usb_mutex);

	/* Assign the format */
	if ((endpoint->bmAttributes &
	    USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH) {
		ctrl = ctrl | HC_EPT_Format;
	}

	maxpacketsize = endpoint->wMaxPacketSize;
	maxpacketsize = maxpacketsize << HC_EPT_MAXPKTSZ;
	ctrl = ctrl | (maxpacketsize & HC_EPT_MPS);

	return (ctrl);
}


/*
 * ohci_insert_ed:
 *
 * Add the Endpoint Descriptor (ED) into the Host Controller's
 * (HC) appropriate endpoint list.
 */
static void
ohci_insert_ed(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	switch (ph->p_ep.bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		ohci_insert_ctrl_ed(ohcip, pp);
		break;
	case USB_EP_ATTR_BULK:
		ohci_insert_bulk_ed(ohcip, pp);
		break;
	case USB_EP_ATTR_INTR:
		ohci_insert_intr_ed(ohcip, pp);
		break;
	case USB_EP_ATTR_ISOCH:
		ohci_insert_isoc_ed(ohcip, pp);
		break;
	}
}


/*
 * ohci_insert_ctrl_ed:
 *
 * Insert a control endpoint into the Host Controller's (HC)
 * control endpoint list.
 */
static void
ohci_insert_ctrl_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t	*ept = pp->pp_ept;
	ohci_ed_t	*prev_ept;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_ctrl_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Obtain a ptr to the head of the list */
	if (Get_OpReg(hcr_ctrl_head)) {
		prev_ept = ohci_ed_iommu_to_cpu(ohcip,
		    Get_OpReg(hcr_ctrl_head));

		/* Set up the backwards pointer */
		Set_ED(prev_ept->hced_prev, ohci_ed_cpu_to_iommu(ohcip, ept));
	}

	/* The new endpoint points to the head of the list */
	Set_ED(ept->hced_next, Get_OpReg(hcr_ctrl_head));

	/* Set the head ptr to the new endpoint */
	Set_OpReg(hcr_ctrl_head, ohci_ed_cpu_to_iommu(ohcip, ept));

	/*
	 * Enable Control list processing if control open
	 * pipe count is zero.
	 */
	if (!ohcip->ohci_open_ctrl_pipe_count) {
		/* Start Control list processing */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) | HCR_CONTROL_CLE));
	}

	ohcip->ohci_open_ctrl_pipe_count++;
}


/*
 * ohci_insert_bulk_ed:
 *
 * Insert a bulk endpoint into the Host Controller's (HC) bulk endpoint list.
 */
static void
ohci_insert_bulk_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*ept = pp->pp_ept;
	ohci_ed_t		*prev_ept;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_bulk_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Obtain a ptr to the head of the Bulk list */
	if (Get_OpReg(hcr_bulk_head)) {
		prev_ept = ohci_ed_iommu_to_cpu(ohcip,
		    Get_OpReg(hcr_bulk_head));

		/* Set up the backwards pointer */
		Set_ED(prev_ept->hced_prev, ohci_ed_cpu_to_iommu(ohcip, ept));
	}

	/* The new endpoint points to the head of the Bulk list */
	Set_ED(ept->hced_next, Get_OpReg(hcr_bulk_head));

	/* Set the Bulk head ptr to the new endpoint */
	Set_OpReg(hcr_bulk_head, ohci_ed_cpu_to_iommu(ohcip, ept));

	/*
	 * Enable Bulk list processing if bulk open pipe
	 * count is zero.
	 */
	if (!ohcip->ohci_open_bulk_pipe_count) {
		/* Start Bulk list processing */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) | HCR_CONTROL_BLE));
	}

	ohcip->ohci_open_bulk_pipe_count++;
}


/*
 * ohci_insert_intr_ed:
 *
 * Insert a interrupt endpoint into the Host Controller's (HC) interrupt
 * lattice tree.
 */
static void
ohci_insert_intr_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*ept = pp->pp_ept;
	ohci_ed_t		*next_lattice_ept, *lattice_ept;
	uint_t			node;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_intr_ed:");

	/*
	 * The appropriate node was found
	 * during the opening of the pipe.
	 */
	node = pp->pp_node;

	if (node >= NUM_STATIC_NODES) {
		/* Get the hcca interrupt table index */
		node = ohci_hcca_intr_index(node);

		/* Get the first endpoint on the list */
		next_lattice_ept = ohci_ed_iommu_to_cpu(ohcip,
		    Get_HCCA(ohcip->ohci_hccap->HccaIntTble[node]));

		/* Update this endpoint to point to it */
		Set_ED(ept->hced_next,
		    ohci_ed_cpu_to_iommu(ohcip, next_lattice_ept));

		/* Put this endpoint at the head of the list */
		Set_HCCA(ohcip->ohci_hccap->HccaIntTble[node],
		    ohci_ed_cpu_to_iommu(ohcip, ept));

		/* The previous pointer is NULL */
		Set_ED(ept->hced_prev, 0);

		/* Update the previous pointer of ept->hced_next */
		if (Get_ED(next_lattice_ept->hced_state) != HC_EPT_STATIC) {
			Set_ED(next_lattice_ept->hced_prev,
			    ohci_ed_cpu_to_iommu(ohcip, ept));
		}
	} else {
		/* Find the lattice endpoint */
		lattice_ept = &ohcip->ohci_ed_pool_addr[node];

		/* Find the next lattice endpoint */
		next_lattice_ept = ohci_ed_iommu_to_cpu(
		    ohcip, Get_ED(lattice_ept->hced_next));

		/*
		 * Update this endpoint to point to the next one in the
		 * lattice.
		 */
		Set_ED(ept->hced_next, Get_ED(lattice_ept->hced_next));

		/* Insert this endpoint into the lattice */
		Set_ED(lattice_ept->hced_next,
		    ohci_ed_cpu_to_iommu(ohcip, ept));

		/* Update the previous pointer */
		Set_ED(ept->hced_prev,
		    ohci_ed_cpu_to_iommu(ohcip, lattice_ept));

		/* Update the previous pointer of ept->hced_next */
		if ((next_lattice_ept) &&
		    (Get_ED(next_lattice_ept->hced_state) != HC_EPT_STATIC)) {

			Set_ED(next_lattice_ept->hced_prev,
			    ohci_ed_cpu_to_iommu(ohcip, ept));
		}
	}

	/*
	 * Enable periodic list processing if periodic (interrupt
	 * and isochronous) open pipe count is zero.
	 */
	if (!ohcip->ohci_open_periodic_pipe_count) {
		ASSERT(!ohcip->ohci_open_isoch_pipe_count);

		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) | HCR_CONTROL_PLE));
	}

	ohcip->ohci_open_periodic_pipe_count++;
}


/*
 * ohci_insert_isoc_ed:
 *
 * Insert a isochronous endpoint into the Host Controller's (HC) interrupt
 * lattice tree. A isochronous endpoint will be inserted at the end of the
 * 1ms interrupt endpoint list.
 */
static void
ohci_insert_isoc_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*next_lattice_ept, *lattice_ept;
	ohci_ed_t		*ept = pp->pp_ept;
	uint_t			node;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_isoc_ed:");

	/*
	 * The appropriate node was found during the opening of the pipe.
	 * This  node must be root of the interrupt lattice tree.
	 */
	node = pp->pp_node;

	ASSERT(node == 0);

	/* Find the 1ms interrupt lattice endpoint */
	lattice_ept = &ohcip->ohci_ed_pool_addr[node];

	/* Find the next lattice endpoint */
	next_lattice_ept = ohci_ed_iommu_to_cpu(
	    ohcip, Get_ED(lattice_ept->hced_next));

	while (next_lattice_ept) {
		lattice_ept = next_lattice_ept;

		/* Find the next lattice endpoint */
		next_lattice_ept = ohci_ed_iommu_to_cpu(
		    ohcip, Get_ED(lattice_ept->hced_next));
	}

	/* The next pointer is NULL */
	Set_ED(ept->hced_next, 0);

	/* Update the previous pointer */
	Set_ED(ept->hced_prev, ohci_ed_cpu_to_iommu(ohcip, lattice_ept));

	/* Insert this endpoint into the lattice */
	Set_ED(lattice_ept->hced_next, ohci_ed_cpu_to_iommu(ohcip, ept));

	/*
	 * Enable periodic and isoch lists processing if isoch
	 * open pipe count is zero.
	 */
	if (!ohcip->ohci_open_isoch_pipe_count) {

		Set_OpReg(hcr_control, (Get_OpReg(hcr_control) |
		    HCR_CONTROL_PLE | HCR_CONTROL_IE));
	}

	ohcip->ohci_open_periodic_pipe_count++;
	ohcip->ohci_open_isoch_pipe_count++;
}


/*
 * ohci_modify_sKip_bit:
 *
 * Modify the sKip bit on the Host Controller (HC) Endpoint Descriptor (ED).
 */
static void
ohci_modify_sKip_bit(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	skip_bit_t		action,
	usb_flags_t		flag)
{
	ohci_ed_t		*ept = pp->pp_ept;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_modify_sKip_bit: action = 0x%x flag = 0x%x",
	    action, flag);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	if (action == CLEAR_sKip) {
		/*
		 * If the skip bit is to be cleared, just clear it.
		 * there shouldn't be any race condition problems.
		 * If the host controller reads the bit before the
		 * driver has a chance to set the bit, the bit will
		 * be reread on the next frame.
		 */
		Set_ED(ept->hced_ctrl, (Get_ED(ept->hced_ctrl) & ~HC_EPT_sKip));
	} else {
		/* Sync ED and TD pool */
		if (flag & OHCI_FLAGS_DMA_SYNC) {
			Sync_ED_TD_Pool(ohcip);
		}

		/* Check Halt or Skip bit is already set */
		if ((Get_ED(ept->hced_headp) & HC_EPT_Halt) ||
		    (Get_ED(ept->hced_ctrl) & HC_EPT_sKip)) {

			USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_modify_sKip_bit: "
			    "Halt or Skip bit is already set");
		} else {
			/*
			 * The action is to set the skip bit.  In order to
			 * be sure that the HCD has seen the sKip bit, wait
			 * for the next start of frame.
			 */
			Set_ED(ept->hced_ctrl,
			    (Get_ED(ept->hced_ctrl) | HC_EPT_sKip));

			if (flag & OHCI_FLAGS_SLEEP) {
				/* Wait for the next SOF */
				(void) ohci_wait_for_sof(ohcip);

				/* Sync ED and TD pool */
				if (flag & OHCI_FLAGS_DMA_SYNC) {
					Sync_ED_TD_Pool(ohcip);
				}
			}
		}
	}
}


/*
 * ohci_remove_ed:
 *
 * Remove the Endpoint Descriptor (ED) from the Host Controller's appropriate
 * endpoint list.
 */
static void
ohci_remove_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	uchar_t			attributes;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_remove_ed:");

	attributes = pp->pp_pipe_handle->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	switch (attributes) {
	case USB_EP_ATTR_CONTROL:
		ohci_remove_ctrl_ed(ohcip, pp);
		break;
	case USB_EP_ATTR_BULK:
		ohci_remove_bulk_ed(ohcip, pp);
		break;
	case USB_EP_ATTR_INTR:
	case USB_EP_ATTR_ISOCH:
		ohci_remove_periodic_ed(ohcip, pp);
		break;
	}
}


/*
 * ohci_remove_ctrl_ed:
 *
 * Remove a control Endpoint Descriptor (ED) from the Host Controller's (HC)
 * control endpoint list.
 */
static void
ohci_remove_ctrl_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*ept = pp->pp_ept; /* ept to be removed */

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_remove_ctrl_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* The control list should already be stopped */
	ASSERT(!(Get_OpReg(hcr_control) & HCR_CONTROL_CLE));

	ohcip->ohci_open_ctrl_pipe_count--;

	/* Detach the endpoint from the list that it's on */
	ohci_detach_ed_from_list(ohcip, ept, USB_EP_ATTR_CONTROL);

	/*
	 * If next endpoint pointed by endpoint to be removed is not NULL
	 * then set current control pointer to the next endpoint pointed by
	 * endpoint to be removed. Otherwise set current control pointer to
	 * the beginning of the control list.
	 */
	if (Get_ED(ept->hced_next)) {
		Set_OpReg(hcr_ctrl_curr, Get_ED(ept->hced_next));
	} else {
		Set_OpReg(hcr_ctrl_curr, Get_OpReg(hcr_ctrl_head));
	}

	if (ohcip->ohci_open_ctrl_pipe_count) {
		ASSERT(Get_OpReg(hcr_ctrl_head));

		/* Reenable the control list */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) | HCR_CONTROL_CLE));
	}

	ohci_insert_ed_on_reclaim_list(ohcip, pp);
}


/*
 * ohci_remove_bulk_ed:
 *
 * Remove free the  bulk Endpoint Descriptor (ED) from the Host Controller's
 * (HC) bulk endpoint list.
 */
static void
ohci_remove_bulk_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*ept = pp->pp_ept;	/* ept to be removed */

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_remove_bulk_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* The bulk list should already be stopped */
	ASSERT(!(Get_OpReg(hcr_control) & HCR_CONTROL_BLE));

	ohcip->ohci_open_bulk_pipe_count--;

	/* Detach the endpoint from the bulk list */
	ohci_detach_ed_from_list(ohcip, ept, USB_EP_ATTR_BULK);

	/*
	 * If next endpoint pointed by endpoint to be removed is not NULL
	 * then set current bulk pointer to the next endpoint pointed by
	 * endpoint to be removed. Otherwise set current bulk pointer to
	 * the beginning of the bulk list.
	 */
	if (Get_ED(ept->hced_next)) {
		Set_OpReg(hcr_bulk_curr, Get_ED(ept->hced_next));
	} else {
		Set_OpReg(hcr_bulk_curr, Get_OpReg(hcr_bulk_head));
	}

	if (ohcip->ohci_open_bulk_pipe_count) {
		ASSERT(Get_OpReg(hcr_bulk_head));

		/* Re-enable the bulk list */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) | HCR_CONTROL_BLE));
	}

	ohci_insert_ed_on_reclaim_list(ohcip, pp);
}


/*
 * ohci_remove_periodic_ed:
 *
 * Set up an periodic endpoint to be removed from the Host Controller's (HC)
 * interrupt lattice tree. The Endpoint Descriptor (ED) will be freed in the
 * interrupt handler.
 */
static void
ohci_remove_periodic_ed(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*ept = pp->pp_ept;	/* ept to be removed */
	uint_t			ept_type;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_remove_periodic_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	ASSERT((Get_ED(ept->hced_tailp) & HC_EPT_TD_TAIL) ==
	    (Get_ED(ept->hced_headp) & HC_EPT_TD_HEAD));

	ohcip->ohci_open_periodic_pipe_count--;

	ept_type = pp->pp_pipe_handle->
	    p_ep.bmAttributes & USB_EP_ATTR_MASK;

	if (ept_type == USB_EP_ATTR_ISOCH) {
		ohcip->ohci_open_isoch_pipe_count--;
	}

	/* Store the node number */
	Set_ED(ept->hced_node, pp->pp_node);

	/* Remove the endpoint from interrupt lattice tree */
	ohci_detach_ed_from_list(ohcip, ept, ept_type);

	/*
	 * Disable isoch list processing if isoch open pipe count
	 * is zero.
	 */
	if (!ohcip->ohci_open_isoch_pipe_count) {
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) & ~(HCR_CONTROL_IE)));
	}

	/*
	 * Disable periodic list processing if periodic (interrupt
	 * and isochrous) open pipe count is zero.
	 */
	if (!ohcip->ohci_open_periodic_pipe_count) {
		ASSERT(!ohcip->ohci_open_isoch_pipe_count);

		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) & ~(HCR_CONTROL_PLE)));
	}

	ohci_insert_ed_on_reclaim_list(ohcip, pp);
}


/*
 * ohci_detach_ed_from_list:
 *
 * Remove the Endpoint Descriptor (ED) from the appropriate Host Controller's
 * (HC) endpoint list.
 */
static void
ohci_detach_ed_from_list(
	ohci_state_t	*ohcip,
	ohci_ed_t	*ept,
	uint_t		ept_type)
{
	ohci_ed_t	*prev_ept;	/* Previous endpoint */
	ohci_ed_t	*next_ept;	/* Endpoint after one to be removed */
	uint_t		node;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_detach_ed_from_list:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	prev_ept = ohci_ed_iommu_to_cpu(ohcip, Get_ED(ept->hced_prev));
	next_ept = ohci_ed_iommu_to_cpu(ohcip, Get_ED(ept->hced_next));

	/*
	 * If there is no previous endpoint, then this
	 * endpoint is at the head of the endpoint list.
	 */
	if (prev_ept == NULL) {
		if (next_ept) {
			/*
			 * If this endpoint is the first element of the
			 * list and there is more  than one endpoint on
			 * the list then perform specific actions based
			 * on the type of endpoint list.
			 */
			switch (ept_type) {
			case USB_EP_ATTR_CONTROL:
				/* Set the head of list to next ept */
				Set_OpReg(hcr_ctrl_head,
				    Get_ED(ept->hced_next));

				/* Clear prev ptr of  next endpoint */
				Set_ED(next_ept->hced_prev, 0);
				break;
			case USB_EP_ATTR_BULK:
				/* Set the head of list to next ept */
				Set_OpReg(hcr_bulk_head,
				    Get_ED(ept->hced_next));

				/* Clear prev ptr of  next endpoint */
				Set_ED(next_ept->hced_prev, 0);
				break;
			case USB_EP_ATTR_INTR:
				/*
				 * HCCA area should point
				 * directly to this ept.
				 */
				ASSERT(Get_ED(ept->hced_node) >=
				    NUM_STATIC_NODES);

				/* Get the hcca interrupt table index */
				node = ohci_hcca_intr_index(
				    Get_ED(ept->hced_node));

				/*
				 * Delete the ept from the
				 * bottom of the tree.
				 */
				Set_HCCA(ohcip->ohci_hccap->
				    HccaIntTble[node], Get_ED(ept->hced_next));

				/*
				 * Update the previous pointer
				 * of ept->hced_next
				 */
				if (Get_ED(next_ept->hced_state) !=
				    HC_EPT_STATIC) {

					Set_ED(next_ept->hced_prev, 0);
				}

				break;
			case USB_EP_ATTR_ISOCH:
			default:
				break;
			}
		} else {
			/*
			 * If there was only one element on the list
			 * perform specific actions based on the type
			 * of the list.
			 */
			switch (ept_type) {
			case USB_EP_ATTR_CONTROL:
				/* Set the head to NULL */
				Set_OpReg(hcr_ctrl_head, 0);
				break;
			case USB_EP_ATTR_BULK:
				/* Set the head to NULL */
				Set_OpReg(hcr_bulk_head, 0);
				break;
			case USB_EP_ATTR_INTR:
			case USB_EP_ATTR_ISOCH:
			default:
				break;
			}
		}
	} else {
		/* The previous ept points to the next one */
		Set_ED(prev_ept->hced_next, Get_ED(ept->hced_next));

		/*
		 * Set the previous ptr of the next_ept to prev_ept
		 * if this isn't the last endpoint on the list
		 */
		if ((next_ept) &&
		    (Get_ED(next_ept->hced_state) != HC_EPT_STATIC)) {

			/* Set the previous ptr of the next one */
			Set_ED(next_ept->hced_prev, Get_ED(ept->hced_prev));
		}
	}
}


/*
 * ohci_insert_ed_on_reclaim_list:
 *
 * Insert Endpoint onto the reclaim list
 */
static void
ohci_insert_ed_on_reclaim_list(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_ed_t		*ept = pp->pp_ept; /* ept to be removed */
	ohci_ed_t		*next_ept, *prev_ept;
	usb_frame_number_t	frame_number;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Read current usb frame number and add appropriate number of
	 * usb frames needs to wait before reclaiming current endpoint.
	 */
	frame_number =
	    ohci_get_current_frame_number(ohcip) + MAX_SOF_WAIT_COUNT;

	/* Store 32bit ID */
	Set_ED(ept->hced_reclaim_frame,
	    ((uint32_t)(OHCI_GET_ID((void *)(uintptr_t)frame_number))));

	/* Insert the endpoint onto the reclaimation list */
	if (ohcip->ohci_reclaim_list) {
		next_ept = ohcip->ohci_reclaim_list;

		while (next_ept) {
			prev_ept = next_ept;
			next_ept = ohci_ed_iommu_to_cpu(ohcip,
			    Get_ED(next_ept->hced_reclaim_next));
		}

		Set_ED(prev_ept->hced_reclaim_next,
		    ohci_ed_cpu_to_iommu(ohcip, ept));
	} else {
		ohcip->ohci_reclaim_list = ept;
	}

	ASSERT(Get_ED(ept->hced_reclaim_next) == NULL);

	/* Enable the SOF interrupt */
	Set_OpReg(hcr_intr_enable, HCR_INTR_SOF);
}


/*
 * ohci_deallocate_ed:
 * NOTE: This function is also called from POLLED MODE.
 *
 * Deallocate a Host Controller's (HC) Endpoint Descriptor (ED).
 */
void
ohci_deallocate_ed(
	ohci_state_t	*ohcip,
	ohci_ed_t	*old_ed)
{
	ohci_td_t	*dummy_td;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_deallocate_ed:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	dummy_td = ohci_td_iommu_to_cpu(ohcip, Get_ED(old_ed->hced_headp));

	if (dummy_td) {

		ASSERT(Get_TD(dummy_td->hctd_state) == HC_TD_DUMMY);
		ohci_deallocate_td(ohcip, dummy_td);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_deallocate_ed: Deallocated 0x%p", (void *)old_ed);

	bzero((void *)old_ed, sizeof (ohci_ed_t));
	Set_ED(old_ed->hced_state, HC_EPT_FREE);
}


/*
 * ohci_ed_cpu_to_iommu:
 * NOTE: This function is also called from POLLED MODE.
 *
 * This function converts for the given Endpoint Descriptor (ED) CPU address
 * to IO address.
 */
uint32_t
ohci_ed_cpu_to_iommu(
	ohci_state_t	*ohcip,
	ohci_ed_t	*addr)
{
	uint32_t	ed;

	ed = (uint32_t)ohcip->ohci_ed_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr - (uintptr_t)(ohcip->ohci_ed_pool_addr));

	ASSERT(ed >= ohcip->ohci_ed_pool_cookie.dmac_address);
	ASSERT(ed <= ohcip->ohci_ed_pool_cookie.dmac_address +
	    sizeof (ohci_ed_t) * ohci_ed_pool_size);

	return (ed);
}


/*
 * ohci_ed_iommu_to_cpu:
 *
 * This function converts for the given Endpoint Descriptor (ED) IO address
 * to CPU address.
 */
static ohci_ed_t *
ohci_ed_iommu_to_cpu(
	ohci_state_t	*ohcip,
	uintptr_t	addr)
{
	ohci_ed_t	*ed;

	if (addr == 0)
		return (NULL);

	ed = (ohci_ed_t *)((uintptr_t)
	    (addr - ohcip->ohci_ed_pool_cookie.dmac_address) +
	    (uintptr_t)ohcip->ohci_ed_pool_addr);

	ASSERT(ed >= ohcip->ohci_ed_pool_addr);
	ASSERT((uintptr_t)ed <= (uintptr_t)ohcip->ohci_ed_pool_addr +
	    (uintptr_t)(sizeof (ohci_ed_t) * ohci_ed_pool_size));

	return (ed);
}


/*
 * Transfer Descriptor manipulations functions
 */

/*
 * ohci_initialize_dummy:
 *
 * An Endpoint Descriptor (ED) has a  dummy Transfer Descriptor (TD) on the
 * end of its TD list. Initially, both the head and tail pointers of the ED
 * point to the dummy TD.
 */
static int
ohci_initialize_dummy(
	ohci_state_t	*ohcip,
	ohci_ed_t	*ept)
{
	ohci_td_t *dummy;

	/* Obtain a  dummy TD */
	dummy = ohci_allocate_td_from_pool(ohcip);

	if (dummy == NULL) {
		return (USB_NO_RESOURCES);
	}

	/*
	 * Both the head and tail pointers of an ED point
	 * to this new dummy TD.
	 */
	Set_ED(ept->hced_headp, (ohci_td_cpu_to_iommu(ohcip, dummy)));
	Set_ED(ept->hced_tailp, (ohci_td_cpu_to_iommu(ohcip, dummy)));

	return (USB_SUCCESS);
}

/*
 * ohci_allocate_ctrl_resources:
 *
 * Calculates the number of tds necessary for a ctrl transfer, and allocates
 * all the resources necessary.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static ohci_trans_wrapper_t *
ohci_allocate_ctrl_resources(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		usb_flags)
{
	size_t			td_count = 2;
	size_t			ctrl_buf_size;
	ohci_trans_wrapper_t	*tw;

	/* Add one more td for data phase */
	if (ctrl_reqp->ctrl_wLength) {
		td_count++;
	}

	/*
	 * If we have a control data phase, the data buffer starts
	 * on the next 4K page boundary. So the TW buffer is allocated
	 * to be larger than required. The buffer in the range of
	 * [SETUP_SIZE, OHCI_MAX_TD_BUF_SIZE) is just for padding
	 * and not to be transferred.
	 */
	if (ctrl_reqp->ctrl_wLength) {
		ctrl_buf_size = OHCI_MAX_TD_BUF_SIZE +
		    ctrl_reqp->ctrl_wLength;
	} else {
		ctrl_buf_size = SETUP_SIZE;
	}

	tw = ohci_allocate_tw_resources(ohcip, pp, ctrl_buf_size,
	    usb_flags, td_count);

	return (tw);
}

/*
 * ohci_insert_ctrl_req:
 *
 * Create a Transfer Descriptor (TD) and a data buffer for a control endpoint.
 */
/* ARGSUSED */
static void
ohci_insert_ctrl_req(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp,
	ohci_trans_wrapper_t	*tw,
	usb_flags_t		usb_flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	uchar_t			bmRequestType = ctrl_reqp->ctrl_bmRequestType;
	uchar_t			bRequest = ctrl_reqp->ctrl_bRequest;
	uint16_t		wValue = ctrl_reqp->ctrl_wValue;
	uint16_t		wIndex = ctrl_reqp->ctrl_wIndex;
	uint16_t		wLength = ctrl_reqp->ctrl_wLength;
	mblk_t			*data = ctrl_reqp->ctrl_data;
	uint32_t		ctrl = 0;
	int			sdata;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_ctrl_req:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Save current control request pointer and timeout values
	 * in transfer wrapper.
	 */
	tw->tw_curr_xfer_reqp = (usb_opaque_t)ctrl_reqp;
	tw->tw_timeout = ctrl_reqp->ctrl_timeout ?
	    ctrl_reqp->ctrl_timeout : OHCI_DEFAULT_XFER_TIMEOUT;

	/*
	 * Initialize the callback and any callback data for when
	 * the td completes.
	 */
	tw->tw_handle_td = ohci_handle_ctrl_td;
	tw->tw_handle_callback_value = NULL;

	/* Create the first four bytes of the setup packet */
	sdata = (bmRequestType << 24) | (bRequest << 16) |
	    (((wValue >> 8) | (wValue << 8)) & 0x0000FFFF);

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_create_setup_pkt: sdata = 0x%x", sdata);

	ddi_put32(tw->tw_accesshandle, (uint_t *)tw->tw_buf, sdata);

	/* Create the second four bytes */
	sdata = (uint32_t)(((((wIndex >> 8) |
	    (wIndex << 8)) << 16) & 0xFFFF0000) |
	    (((wLength >> 8) | (wLength << 8)) & 0x0000FFFF));

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_create_setup_pkt: sdata = 0x%x", sdata);

	ddi_put32(tw->tw_accesshandle,
	    (uint_t *)((uintptr_t)tw->tw_buf + sizeof (uint_t)), sdata);

	ctrl = HC_TD_SETUP|HC_TD_MS_DT|HC_TD_DT_0|HC_TD_6I;

	/*
	 * The TD's are placed on the ED one at a time.
	 * Once this TD is placed on the done list, the
	 * data or status phase TD will be enqueued.
	 */
	(void) ohci_insert_hc_td(ohcip, ctrl, 0, SETUP_SIZE,
	    OHCI_CTRL_SETUP_PHASE, pp, tw);

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "Create_setup: pp 0x%p", (void *)pp);

	/*
	 * If this control transfer has a data phase, record the
	 * direction. If the data phase is an OUT transaction,
	 * copy the data into the buffer of the transfer wrapper.
	 */
	if (wLength != 0) {
		/* There is a data stage.  Find the direction */
		if (bmRequestType & USB_DEV_REQ_DEV_TO_HOST) {
			tw->tw_direction = HC_TD_IN;
		} else {
			tw->tw_direction = HC_TD_OUT;

			/* Copy the data into the message */
			ddi_rep_put8(tw->tw_accesshandle, data->b_rptr,
			    (uint8_t *)(tw->tw_buf + OHCI_MAX_TD_BUF_SIZE),
			    wLength, DDI_DEV_AUTOINCR);

		}

		ctrl = (ctrl_reqp->ctrl_attributes & USB_ATTRS_SHORT_XFER_OK) ?
		    HC_TD_R : 0;

		/*
		 * There is a data stage.
		 * Find the direction.
		 */
		if (tw->tw_direction == HC_TD_IN) {
			ctrl = ctrl|HC_TD_IN|HC_TD_MS_DT|HC_TD_DT_1|HC_TD_6I;
		} else {
			ctrl = ctrl|HC_TD_OUT|HC_TD_MS_DT|HC_TD_DT_1|HC_TD_6I;
		}

		/*
		 * Create the TD.  If this is an OUT transaction,
		 * the data is already in the buffer of the TW.
		 */
		(void) ohci_insert_hc_td(ohcip, ctrl, OHCI_MAX_TD_BUF_SIZE,
		    wLength, OHCI_CTRL_DATA_PHASE, pp, tw);

		/*
		 * The direction of the STATUS TD depends on
		 * the direction of the transfer.
		 */
		if (tw->tw_direction == HC_TD_IN) {
			ctrl = HC_TD_OUT|HC_TD_MS_DT|HC_TD_DT_1|HC_TD_1I;
		} else {
			ctrl = HC_TD_IN|HC_TD_MS_DT|HC_TD_DT_1|HC_TD_1I;
		}
	} else {
		ctrl = HC_TD_IN|HC_TD_MS_DT|HC_TD_DT_1|HC_TD_1I;
	}

	/* Status stage */
	(void) ohci_insert_hc_td(ohcip, ctrl, 0,
	    0, OHCI_CTRL_STATUS_PHASE, pp, tw);

	/* Indicate that the control list is filled */
	Set_OpReg(hcr_cmd_status, HCR_STATUS_CLF);

	/* Start the timer for this control transfer */
	ohci_start_xfer_timer(ohcip, pp, tw);
}

/*
 * ohci_allocate_bulk_resources:
 *
 * Calculates the number of tds necessary for a ctrl transfer, and allocates
 * all the resources necessary.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static ohci_trans_wrapper_t *
ohci_allocate_bulk_resources(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	usb_bulk_req_t		*bulk_reqp,
	usb_flags_t		usb_flags)
{
	size_t			td_count = 0;
	ohci_trans_wrapper_t	*tw;

	/* Check the size of bulk request */
	if (bulk_reqp->bulk_len > OHCI_MAX_BULK_XFER_SIZE) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_allocate_bulk_resources: Bulk request size 0x%x is "
		    "more than 0x%x", bulk_reqp->bulk_len,
		    OHCI_MAX_BULK_XFER_SIZE);

		return (NULL);
	}

	/* Get the required bulk packet size */
	td_count = bulk_reqp->bulk_len / OHCI_MAX_TD_XFER_SIZE;
	if (bulk_reqp->bulk_len % OHCI_MAX_TD_XFER_SIZE ||
	    bulk_reqp->bulk_len == 0) {
		td_count++;
	}

	tw = ohci_allocate_tw_resources(ohcip, pp, bulk_reqp->bulk_len,
	    usb_flags, td_count);

	return (tw);
}

/*
 * ohci_insert_bulk_req:
 *
 * Create a Transfer Descriptor (TD) and a data buffer for a bulk
 * endpoint.
 */
/* ARGSUSED */
static void
ohci_insert_bulk_req(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_bulk_req_t		*bulk_reqp,
	ohci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	uint_t			bulk_pkt_size, count;
	size_t			residue = 0, len = 0;
	uint32_t		ctrl = 0;
	int			pipe_dir;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_bulk_req: bulk_reqp = 0x%p flags = 0x%x",
	    (void *)bulk_reqp, flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Get the bulk pipe direction */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	/* Get the required bulk packet size */
	bulk_pkt_size = min(bulk_reqp->bulk_len, OHCI_MAX_TD_XFER_SIZE);

	if (bulk_pkt_size)
		residue = tw->tw_length % bulk_pkt_size;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_bulk_req: bulk_pkt_size = %d", bulk_pkt_size);

	/*
	 * Save current bulk request pointer and timeout values
	 * in transfer wrapper.
	 */
	tw->tw_curr_xfer_reqp = (usb_opaque_t)bulk_reqp;
	tw->tw_timeout = bulk_reqp->bulk_timeout;

	/*
	 * Initialize the callback and any callback
	 * data required when the td completes.
	 */
	tw->tw_handle_td = ohci_handle_bulk_td;
	tw->tw_handle_callback_value = NULL;

	tw->tw_direction =
	    (pipe_dir == USB_EP_DIR_OUT) ? HC_TD_OUT : HC_TD_IN;

	if (tw->tw_direction == HC_TD_OUT && bulk_reqp->bulk_len) {

		ASSERT(bulk_reqp->bulk_data != NULL);

		/* Copy the data into the message */
		ddi_rep_put8(tw->tw_accesshandle,
		    bulk_reqp->bulk_data->b_rptr, (uint8_t *)tw->tw_buf,
		    bulk_reqp->bulk_len, DDI_DEV_AUTOINCR);
	}

	ctrl = tw->tw_direction|HC_TD_DT_0|HC_TD_6I;

	/* Insert all the bulk TDs */
	for (count = 0; count < tw->tw_num_tds; count++) {

		/* Check for last td */
		if (count == (tw->tw_num_tds - 1)) {

			ctrl = ((ctrl & ~HC_TD_DI) | HC_TD_1I);

			/* Check for inserting residue data */
			if (residue) {
				bulk_pkt_size = (uint_t)residue;
			}

			/*
			 * Only set the round bit on the last TD, to ensure
			 * the controller will always HALT the ED in case of
			 * a short transfer.
			 */
			if (bulk_reqp->bulk_attributes &
			    USB_ATTRS_SHORT_XFER_OK) {
				ctrl |= HC_TD_R;
			}
		}

		/* Insert the TD onto the endpoint */
		(void) ohci_insert_hc_td(ohcip, ctrl, len,
		    bulk_pkt_size, 0, pp, tw);

		len = len + bulk_pkt_size;
	}

	/* Indicate that the bulk list is filled */
	Set_OpReg(hcr_cmd_status, HCR_STATUS_BLF);

	/* Start the timer for this bulk transfer */
	ohci_start_xfer_timer(ohcip, pp, tw);
}


/*
 * ohci_start_periodic_pipe_polling:
 * NOTE: This function is also called from POLLED MODE.
 */
int
ohci_start_periodic_pipe_polling(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_opaque_t		periodic_in_reqp,
	usb_flags_t		flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_start_periodic_pipe_polling: ep%d",
	    ph->p_ep.bEndpointAddress & USB_EP_NUM_MASK);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Check and handle start polling on root hub interrupt pipe.
	 */
	if ((ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) &&
	    ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_INTR)) {

		error = ohci_handle_root_hub_pipe_start_intr_polling(ph,
		    (usb_intr_req_t *)periodic_in_reqp, flags);

		return (error);
	}

	switch (pp->pp_state) {
	case OHCI_PIPE_STATE_IDLE:
		/* Save the Original client's Periodic IN request */
		pp->pp_client_periodic_in_reqp = periodic_in_reqp;

		/*
		 * This pipe is uninitialized or if a valid TD is
		 * not found then insert a TD on the interrupt or
		 * isochronous IN endpoint.
		 */
		error = ohci_start_pipe_polling(ohcip, ph, flags);

		if (error != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_start_periodic_pipe_polling: "
			    "Start polling failed");

			pp->pp_client_periodic_in_reqp = NULL;

			return (error);
		}

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_start_periodic_pipe_polling: PP = 0x%p", (void *)pp);

		ASSERT((pp->pp_tw_head != NULL) && (pp->pp_tw_tail != NULL));

		break;
	case OHCI_PIPE_STATE_ACTIVE:
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_start_periodic_pipe_polling: "
		    "Polling is already in progress");

		error = USB_FAILURE;
		break;
	case OHCI_PIPE_STATE_ERROR:
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_start_periodic_pipe_polling: "
		    "Pipe is halted and perform reset before restart polling");

		error = USB_FAILURE;
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_start_periodic_pipe_polling: Undefined state");

		error = USB_FAILURE;
		break;
	}

	return (error);
}


/*
 * ohci_start_pipe_polling:
 *
 * Insert the number of periodic requests corresponding to polling
 * interval as calculated during pipe open.
 */
static int
ohci_start_pipe_polling(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	ohci_trans_wrapper_t	*tw_list, *tw;
	int			i, total_tws;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_start_pipe_polling:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * For the start polling, pp_max_periodic_req_cnt will be zero
	 * and for the restart polling request, it will be non zero.
	 *
	 * In case of start polling request, find out number of requests
	 * required for the Interrupt IN endpoints corresponding to the
	 * endpoint polling interval. For Isochronous IN endpoints, it is
	 * always fixed since its polling interval will be one ms.
	 */
	if (pp->pp_max_periodic_req_cnt == 0) {

		ohci_set_periodic_pipe_polling(ohcip, ph);
	}

	ASSERT(pp->pp_max_periodic_req_cnt != 0);

	/* Allocate all the necessary resources for the IN transfer */
	tw_list = NULL;
	total_tws = pp->pp_max_periodic_req_cnt - pp->pp_cur_periodic_req_cnt;
	for (i = 0; i < total_tws; i++) {
		switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_INTR:
			tw = ohci_allocate_intr_resources(
			    ohcip, ph, NULL, flags);
			break;
		case USB_EP_ATTR_ISOCH:
			tw = ohci_allocate_isoc_resources(
			    ohcip, ph, NULL, flags);
			break;
		}
		if (tw == NULL) {
			error = USB_NO_RESOURCES;
			/* There are not enough resources, deallocate the TWs */
			tw = tw_list;
			while (tw != NULL) {
				tw_list = tw->tw_next;
				ohci_deallocate_periodic_in_resource(
				    ohcip, pp, tw);
				ohci_deallocate_tw_resources(ohcip, pp, tw);
				tw = tw_list;
			}
			return (error);
		} else {
			if (tw_list == NULL) {
				tw_list = tw;
			}
		}
	}

	i = 0;
	while (pp->pp_cur_periodic_req_cnt < pp->pp_max_periodic_req_cnt) {

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_start_pipe_polling: max = %d curr = %d tw = %p:",
		    pp->pp_max_periodic_req_cnt, pp->pp_cur_periodic_req_cnt,
		    (void *)tw_list);

		tw = tw_list;
		tw_list = tw->tw_next;

		switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_INTR:
			ohci_insert_intr_req(ohcip, pp, tw, flags);
			break;
		case USB_EP_ATTR_ISOCH:
			error = ohci_insert_isoc_req(ohcip, pp, tw, flags);
			break;
		}
		if (error == USB_SUCCESS) {
			pp->pp_cur_periodic_req_cnt++;
		} else {
			/*
			 * Deallocate the remaining tw
			 * The current tw should have already been deallocated
			 */
			tw = tw_list;
			while (tw != NULL) {
				tw_list = tw->tw_next;
				ohci_deallocate_periodic_in_resource(
				    ohcip, pp, tw);
				ohci_deallocate_tw_resources(ohcip, pp, tw);
				tw = tw_list;
			}
			/*
			 * If this is the first req return an error.
			 * Otherwise return success.
			 */
			if (i != 0) {
				error = USB_SUCCESS;
			}

			break;
		}
		i++;
	}

	return (error);
}


/*
 * ohci_set_periodic_pipe_polling:
 *
 * Calculate the number of periodic requests needed corresponding to the
 * interrupt/isochronous IN endpoints polling interval. Table below gives
 * the number of periodic requests needed for the interrupt/isochronous
 * IN endpoints according to endpoint polling interval.
 *
 * Polling interval		Number of periodic requests
 *
 * 1ms				4
 * 2ms				2
 * 4ms to 32ms			1
 */
static void
ohci_set_periodic_pipe_polling(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	uchar_t			ep_attr = endpoint->bmAttributes;
	uint_t			interval;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_set_periodic_pipe_polling:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	pp->pp_cur_periodic_req_cnt = 0;

	/*
	 * Check usb flag whether USB_FLAGS_ONE_TIME_POLL flag is
	 * set and if so, set pp->pp_max_periodic_req_cnt to one.
	 */
	if (((ep_attr & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) &&
	    (pp->pp_client_periodic_in_reqp)) {
		usb_intr_req_t *intr_reqp =
		    (usb_intr_req_t *)pp->pp_client_periodic_in_reqp;

		if (intr_reqp->intr_attributes &
		    USB_ATTRS_ONE_XFER) {

			pp->pp_max_periodic_req_cnt = INTR_XMS_REQS;

			return;
		}
	}

	mutex_enter(&ph->p_usba_device->usb_mutex);

	/*
	 * The ohci_adjust_polling_interval function will not fail
	 * at this instance since bandwidth allocation is already
	 * done. Here we are getting only the periodic interval.
	 */
	interval = ohci_adjust_polling_interval(ohcip, endpoint,
	    ph->p_usba_device->usb_port_status);

	mutex_exit(&ph->p_usba_device->usb_mutex);

	switch (interval) {
	case INTR_1MS_POLL:
		pp->pp_max_periodic_req_cnt = INTR_1MS_REQS;
		break;
	case INTR_2MS_POLL:
		pp->pp_max_periodic_req_cnt = INTR_2MS_REQS;
		break;
	default:
		pp->pp_max_periodic_req_cnt = INTR_XMS_REQS;
		break;
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_set_periodic_pipe_polling: Max periodic requests = %d",
	    pp->pp_max_periodic_req_cnt);
}

/*
 * ohci_allocate_intr_resources:
 *
 * Calculates the number of tds necessary for a intr transfer, and allocates
 * all the necessary resources.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static ohci_trans_wrapper_t *
ohci_allocate_intr_resources(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*intr_reqp,
	usb_flags_t		flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	int			pipe_dir;
	size_t			td_count = 1;
	size_t			tw_length;
	ohci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_allocate_intr_resources:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	/* Get the length of interrupt transfer & alloc data */
	if (intr_reqp) {
		tw_length = intr_reqp->intr_len;
	} else {
		ASSERT(pipe_dir == USB_EP_DIR_IN);
		tw_length = (pp->pp_client_periodic_in_reqp) ?
		    (((usb_intr_req_t *)pp->
		    pp_client_periodic_in_reqp)->intr_len) :
		    ph->p_ep.wMaxPacketSize;
	}

	/* Check the size of interrupt request */
	if (tw_length > OHCI_MAX_TD_XFER_SIZE) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_allocate_intr_resources: Intr request size 0x%lx is "
		    "more than 0x%x", tw_length, OHCI_MAX_TD_XFER_SIZE);

		return (NULL);
	}

	if ((tw = ohci_allocate_tw_resources(ohcip, pp, tw_length,
	    flags, td_count)) == NULL) {

		return (NULL);
	}

	if (pipe_dir == USB_EP_DIR_IN) {
		if (ohci_allocate_periodic_in_resource(ohcip, pp, tw, flags) !=
		    USB_SUCCESS) {

			ohci_deallocate_tw_resources(ohcip, pp, tw);
			return (NULL);
		}
		tw->tw_direction = HC_TD_IN;
	} else {
		if (tw_length) {
			ASSERT(intr_reqp->intr_data != NULL);

			/* Copy the data into the message */
			ddi_rep_put8(tw->tw_accesshandle,
			    intr_reqp->intr_data->b_rptr, (uint8_t *)tw->tw_buf,
			    intr_reqp->intr_len, DDI_DEV_AUTOINCR);
		}

		tw->tw_curr_xfer_reqp = (usb_opaque_t)intr_reqp;
		tw->tw_direction = HC_TD_OUT;
	}

	if (intr_reqp) {
		tw->tw_timeout = intr_reqp->intr_timeout;
	}

	/*
	 * Initialize the callback and any callback
	 * data required when the td completes.
	 */
	tw->tw_handle_td = ohci_handle_intr_td;
	tw->tw_handle_callback_value = NULL;

	return (tw);
}

/*
 * ohci_insert_intr_req:
 *
 * Insert an Interrupt request into the Host Controller's periodic list.
 */
/* ARGSUSED */
static void
ohci_insert_intr_req(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	usb_intr_req_t		*curr_intr_reqp = NULL;
	uint_t			ctrl = 0;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	ASSERT(tw->tw_curr_xfer_reqp != NULL);

	/* Get the current interrupt request pointer */
	curr_intr_reqp = (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

	ctrl = tw->tw_direction | HC_TD_DT_0 | HC_TD_1I;

	if (curr_intr_reqp->intr_attributes & USB_ATTRS_SHORT_XFER_OK) {
		ctrl |= HC_TD_R;
	}

	/* Insert another interrupt TD */
	(void) ohci_insert_hc_td(ohcip, ctrl, 0, tw->tw_length, 0, pp, tw);

	/* Start the timer for this Interrupt transfer */
	ohci_start_xfer_timer(ohcip, pp, tw);
}


/*
 * ohci_stop_periodic_pipe_polling:
 */
/* ARGSUSED */
static int
ohci_stop_periodic_pipe_polling(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_stop_periodic_pipe_polling: Flags = 0x%x", flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Check and handle stop polling on root hub interrupt pipe.
	 */
	if ((ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) &&
	    ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_INTR)) {

		ohci_handle_root_hub_pipe_stop_intr_polling(
		    ph, flags);
		return (USB_SUCCESS);
	}

	if (pp->pp_state != OHCI_PIPE_STATE_ACTIVE) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_stop_periodic_pipe_polling: Polling already stopped");

		return (USB_SUCCESS);
	}

	/* Set pipe state to pipe stop polling */
	pp->pp_state = OHCI_PIPE_STATE_STOP_POLLING;

	ohci_pipe_cleanup(ohcip, ph);

	return (USB_SUCCESS);
}

/*
 * ohci_allocate_isoc_resources:
 *
 * Calculates the number of tds necessary for a intr transfer, and allocates
 * all the necessary resources.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static ohci_trans_wrapper_t *
ohci_allocate_isoc_resources(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		flags)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	int			pipe_dir;
	uint_t			max_pkt_size = ph->p_ep.wMaxPacketSize;
	uint_t			max_isoc_xfer_size;
	usb_isoc_pkt_descr_t	*isoc_pkt_descr, *start_isoc_pkt_descr;
	ushort_t		isoc_pkt_count;
	size_t			count, td_count;
	size_t			tw_length;
	size_t			isoc_pkts_length;
	ohci_trans_wrapper_t	*tw;


	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_allocate_isoc_resources: flags = ox%x", flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 *  Check whether pipe is in halted state.
	 */
	if (pp->pp_state == OHCI_PIPE_STATE_ERROR) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_allocate_isoc_resources:"
		    "Pipe is in error state, need pipe reset to continue");

		return (NULL);
	}

	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	/* Calculate the maximum isochronous transfer size */
	max_isoc_xfer_size = OHCI_MAX_ISOC_PKTS_PER_XFER * max_pkt_size;

	if (isoc_reqp) {
		isoc_pkt_descr = isoc_reqp->isoc_pkt_descr;
		isoc_pkt_count = isoc_reqp->isoc_pkts_count;
		isoc_pkts_length = isoc_reqp->isoc_pkts_length;
	} else {
		isoc_pkt_descr = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkt_descr;

		isoc_pkt_count = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkts_count;

		isoc_pkts_length = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkts_length;
	}

	start_isoc_pkt_descr = isoc_pkt_descr;

	/*
	 * For isochronous IN pipe, get value of number of isochronous
	 * packets per usb isochronous request
	 */
	if (pipe_dir == USB_EP_DIR_IN) {
		for (count = 0, tw_length = 0;
		    count < isoc_pkt_count; count++) {
			tw_length += isoc_pkt_descr->isoc_pkt_length;
			isoc_pkt_descr++;
		}

		if ((isoc_pkts_length) && (isoc_pkts_length != tw_length)) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_allocate_isoc_resources: "
			    "isoc_pkts_length 0x%lx is not equal to the sum of "
			    "all pkt lengths 0x%lx in an isoc request",
			    isoc_pkts_length, tw_length);

			return (NULL);
		}

	} else {
		ASSERT(isoc_reqp != NULL);
		tw_length = MBLKL(isoc_reqp->isoc_data);
	}

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_allocate_isoc_resources: length = 0x%lx", tw_length);

	/* Check the size of isochronous request */
	if (tw_length > max_isoc_xfer_size) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_allocate_isoc_resources: Maximum isoc request"
		    "size 0x%x Given isoc request size 0x%lx",
		    max_isoc_xfer_size, tw_length);

		return (NULL);
	}

	/*
	 * Each isochronous TD can hold data upto eight isochronous
	 * data packets. Calculate the number of isochronous TDs needs
	 * to be insert to complete current isochronous request.
	 */
	td_count = isoc_pkt_count / OHCI_ISOC_PKTS_PER_TD;

	if (isoc_pkt_count % OHCI_ISOC_PKTS_PER_TD) {
		td_count++;
	}

	tw = ohci_create_isoc_transfer_wrapper(ohcip, pp, tw_length,
	    start_isoc_pkt_descr, isoc_pkt_count, td_count, flags);

	if (tw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_create_isoc_transfer_wrapper: "
		    "Unable to allocate TW");

		return (NULL);
	}

	if (ohci_allocate_tds_for_tw(ohcip, tw, td_count) ==
	    USB_SUCCESS) {
		tw->tw_num_tds = (uint_t)td_count;
	} else {
		ohci_deallocate_tw_resources(ohcip, pp, tw);

		return (NULL);
	}

	if (pipe_dir == USB_EP_DIR_IN) {
		if (ohci_allocate_periodic_in_resource(ohcip, pp, tw, flags) !=
		    USB_SUCCESS) {

			ohci_deallocate_tw_resources(ohcip, pp, tw);
			return (NULL);
		}
		tw->tw_direction = HC_TD_IN;
	} else {
		if (tw->tw_length) {
			uchar_t *p;
			int i;

			ASSERT(isoc_reqp->isoc_data != NULL);
			p = isoc_reqp->isoc_data->b_rptr;

			/* Copy the data into the message */
			for (i = 0; i < td_count; i++) {
				ddi_rep_put8(
				    tw->tw_isoc_bufs[i].mem_handle, p,
				    (uint8_t *)tw->tw_isoc_bufs[i].buf_addr,
				    tw->tw_isoc_bufs[i].length,
				    DDI_DEV_AUTOINCR);
				p += tw->tw_isoc_bufs[i].length;
			}
		}
		tw->tw_curr_xfer_reqp = (usb_opaque_t)isoc_reqp;
		tw->tw_direction = HC_TD_OUT;
	}

	/*
	 * Initialize the callback and any callback
	 * data required when the td completes.
	 */
	tw->tw_handle_td = ohci_handle_isoc_td;
	tw->tw_handle_callback_value = NULL;

	return (tw);
}

/*
 * ohci_insert_isoc_req:
 *
 * Insert an isochronous request into the Host Controller's
 * isochronous list.  If there is an error is will appropriately
 * deallocate the unused resources.
 */
static int
ohci_insert_isoc_req(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	uint_t			flags)
{
	size_t			curr_isoc_xfer_offset, curr_isoc_xfer_len;
	uint_t			isoc_pkts, residue, count;
	uint_t			i, ctrl, frame_count;
	uint_t			error = USB_SUCCESS;
	usb_isoc_req_t		*curr_isoc_reqp;
	usb_isoc_pkt_descr_t	*curr_isoc_pkt_descr;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_isoc_req: flags = 0x%x", flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Get the current isochronous request and packet
	 * descriptor pointers.
	 */
	curr_isoc_reqp = (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;
	curr_isoc_pkt_descr = curr_isoc_reqp->isoc_pkt_descr;

	ASSERT(curr_isoc_reqp != NULL);
	ASSERT(curr_isoc_reqp->isoc_pkt_descr != NULL);

	/*
	 * Save address of first usb isochronous packet descriptor.
	 */
	tw->tw_curr_isoc_pktp = curr_isoc_reqp->isoc_pkt_descr;

	/* Insert all the isochronous TDs */
	for (count = 0, curr_isoc_xfer_offset = 0,
	    isoc_pkts = 0; count < tw->tw_num_tds; count++) {

		residue = curr_isoc_reqp->isoc_pkts_count - isoc_pkts;

		/* Check for inserting residue data */
		if ((count == (tw->tw_num_tds - 1)) &&
		    (residue < OHCI_ISOC_PKTS_PER_TD)) {
			frame_count = residue;
		} else {
			frame_count = OHCI_ISOC_PKTS_PER_TD;
		}

		curr_isoc_pkt_descr = tw->tw_curr_isoc_pktp;

		/*
		 * Calculate length of isochronous transfer
		 * for the current TD.
		 */
		for (i = 0, curr_isoc_xfer_len = 0;
		    i < frame_count; i++, curr_isoc_pkt_descr++) {
			curr_isoc_xfer_len +=
			    curr_isoc_pkt_descr->isoc_pkt_length;
		}

		/*
		 * Programm td control field by checking whether this
		 * is last td.
		 */
		if (count == (tw->tw_num_tds - 1)) {
			ctrl = ((((frame_count - 1) << HC_ITD_FC_SHIFT) &
			    HC_ITD_FC) | HC_TD_DT_0 | HC_TD_0I);
		} else {
			ctrl = ((((frame_count - 1) << HC_ITD_FC_SHIFT) &
			    HC_ITD_FC) | HC_TD_DT_0 | HC_TD_6I);
		}

		/* Insert the TD into the endpoint */
		if ((error = ohci_insert_hc_td(ohcip, ctrl, count,
		    curr_isoc_xfer_len, 0, pp, tw)) !=
		    USB_SUCCESS) {
			tw->tw_num_tds = count;
			tw->tw_length  = curr_isoc_xfer_offset;
			break;
		}

		isoc_pkts += frame_count;
		tw->tw_curr_isoc_pktp += frame_count;
		curr_isoc_xfer_offset += curr_isoc_xfer_len;
	}

	if (error != USB_SUCCESS) {
		/* Free periodic in resources */
		if (tw->tw_direction == USB_EP_DIR_IN) {
			ohci_deallocate_periodic_in_resource(ohcip, pp, tw);
		}

		/* Free all resources if IN or if count == 0(for both IN/OUT) */
		if (tw->tw_direction == USB_EP_DIR_IN || count == 0) {

			ohci_deallocate_tw_resources(ohcip, pp, tw);

			if (pp->pp_cur_periodic_req_cnt) {
				/*
				 * Set pipe state to stop polling and
				 * error to no resource. Don't insert
				 * any more isochronous polling requests.
				 */
				pp->pp_state = OHCI_PIPE_STATE_STOP_POLLING;
				pp->pp_error = error;
			} else {
				/* Set periodic in pipe state to idle */
				pp->pp_state = OHCI_PIPE_STATE_IDLE;
			}
		}
	} else {

		/*
		 * Reset back to the address of first usb isochronous
		 * packet descriptor.
		 */
		tw->tw_curr_isoc_pktp = curr_isoc_reqp->isoc_pkt_descr;

		/* Reset the CONTINUE flag */
		pp->pp_flag &= ~OHCI_ISOC_XFER_CONTINUE;
	}

	return (error);
}


/*
 * ohci_insert_hc_td:
 *
 * Insert a Transfer Descriptor (TD) on an Endpoint Descriptor (ED).
 * Always returns USB_SUCCESS, except for ISOCH.
 */
static int
ohci_insert_hc_td(
	ohci_state_t		*ohcip,
	uint_t			hctd_ctrl,
	uint32_t		hctd_dma_offs,
	size_t			hctd_length,
	uint32_t		hctd_ctrl_phase,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	ohci_td_t		*new_dummy;
	ohci_td_t		*cpu_current_dummy;
	ohci_ed_t		*ept = pp->pp_ept;
	int			error;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Retrieve preallocated td from the TW */
	new_dummy = tw->tw_hctd_free_list;

	ASSERT(new_dummy != NULL);

	tw->tw_hctd_free_list = ohci_td_iommu_to_cpu(ohcip,
	    Get_TD(new_dummy->hctd_tw_next_td));
	Set_TD(new_dummy->hctd_tw_next_td, NULL);

	/* Fill in the current dummy */
	cpu_current_dummy = (ohci_td_t *)
	    (ohci_td_iommu_to_cpu(ohcip, Get_ED(ept->hced_tailp)));

	/*
	 * Fill in the current dummy td and
	 * add the new dummy to the end.
	 */
	ohci_fill_in_td(ohcip, cpu_current_dummy, new_dummy,
	    hctd_ctrl, hctd_dma_offs, hctd_length, hctd_ctrl_phase, pp, tw);

	/*
	 * If this is an isochronous TD, first write proper
	 * starting usb frame number in which this TD must
	 * can be processed. After writing the frame number
	 * insert this TD into the ED's list.
	 */
	if ((pp->pp_pipe_handle->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH) {

		error = ohci_insert_td_with_frame_number(
		    ohcip, pp, tw, cpu_current_dummy, new_dummy);

		if (error != USB_SUCCESS) {
			/* Reset the current dummy back to a dummy */
			bzero((char *)cpu_current_dummy, sizeof (ohci_td_t));
			Set_TD(cpu_current_dummy->hctd_state, HC_TD_DUMMY);

			/* return the new dummy back to the free list */
			bzero((char *)new_dummy, sizeof (ohci_td_t));
			Set_TD(new_dummy->hctd_state, HC_TD_DUMMY);
			if (tw->tw_hctd_free_list != NULL) {
				Set_TD(new_dummy->hctd_tw_next_td,
				    ohci_td_cpu_to_iommu(ohcip,
				    tw->tw_hctd_free_list));
			}
			tw->tw_hctd_free_list = new_dummy;

			return (error);
		}
	} else {
		/*
		 * For control, bulk and interrupt TD, just
		 * add the new dummy to the ED's list. When
		 * this occurs, the Host Controller ill see
		 * the newly filled in dummy TD.
		 */
		Set_ED(ept->hced_tailp,
		    (ohci_td_cpu_to_iommu(ohcip, new_dummy)));
	}

	/* Insert this td onto the tw */
	ohci_insert_td_on_tw(ohcip, tw, cpu_current_dummy);

	return (USB_SUCCESS);
}


/*
 * ohci_allocate_td_from_pool:
 *
 * Allocate a Transfer Descriptor (TD) from the TD buffer pool.
 */
static ohci_td_t *
ohci_allocate_td_from_pool(ohci_state_t	*ohcip)
{
	int				i, state;
	ohci_td_t			*td;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Search for a blank Transfer Descriptor (TD)
	 * in the TD buffer pool.
	 */
	for (i = 0; i < ohci_td_pool_size; i ++) {
		state = Get_TD(ohcip->ohci_td_pool_addr[i].hctd_state);
		if (state == HC_TD_FREE) {
			break;
		}
	}

	if (i >= ohci_td_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
		    "ohci_allocate_td_from_pool: TD exhausted");

		return (NULL);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_allocate_td_from_pool: Allocated %d", i);

	/* Create a new dummy for the end of the TD list */
	td = &ohcip->ohci_td_pool_addr[i];

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_allocate_td_from_pool: td 0x%p", (void *)td);

	/* Mark the newly allocated TD as a dummy */
	Set_TD(td->hctd_state, HC_TD_DUMMY);

	return (td);
}

/*
 * ohci_fill_in_td:
 *
 * Fill in the fields of a Transfer Descriptor (TD).
 *
 * hctd_dma_offs - different meanings for non-isoc and isoc TDs:
 *	    starting offset into the TW buffer for a non-isoc TD
 *	    and the index into the isoc TD list for an isoc TD.
 *	    For non-isoc TDs, the starting offset should be 4k
 *	    aligned and the TDs in one transfer must be filled in
 *	    increasing order.
 */
static void
ohci_fill_in_td(
	ohci_state_t		*ohcip,
	ohci_td_t		*td,
	ohci_td_t		*new_dummy,
	uint_t			hctd_ctrl,
	uint32_t		hctd_dma_offs,
	size_t			hctd_length,
	uint32_t		hctd_ctrl_phase,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_fill_in_td: td 0x%p bufoffs 0x%x len 0x%lx",
	    (void *)td, hctd_dma_offs, hctd_length);

	/* Assert that the td to be filled in is a dummy */
	ASSERT(Get_TD(td->hctd_state) == HC_TD_DUMMY);

	/* Change TD's state Active */
	Set_TD(td->hctd_state, HC_TD_ACTIVE);

	/* Update the TD special fields */
	if ((pp->pp_pipe_handle->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH) {
		ohci_init_itd(ohcip, tw, hctd_ctrl, hctd_dma_offs, td);
	} else {
		/* Update the dummy with control information */
		Set_TD(td->hctd_ctrl, (hctd_ctrl | HC_TD_CC_NA));

		ohci_init_td(ohcip, tw, hctd_dma_offs, hctd_length, td);
	}

	/* The current dummy now points to the new dummy */
	Set_TD(td->hctd_next_td, (ohci_td_cpu_to_iommu(ohcip, new_dummy)));

	/*
	 * For Control transfer, hctd_ctrl_phase is a valid field.
	 */
	if (hctd_ctrl_phase) {
		Set_TD(td->hctd_ctrl_phase, hctd_ctrl_phase);
	}

	/* Print the td */
	ohci_print_td(ohcip, td);

	/* Fill in the wrapper portion of the TD */

	/* Set the transfer wrapper */
	ASSERT(tw != NULL);
	ASSERT(tw->tw_id != NULL);

	Set_TD(td->hctd_trans_wrapper, (uint32_t)tw->tw_id);
	Set_TD(td->hctd_tw_next_td, NULL);
}


/*
 * ohci_init_td:
 *
 * Initialize the buffer address portion of non-isoc Transfer
 * Descriptor (TD).
 */
void
ohci_init_td(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw,
	uint32_t		hctd_dma_offs,
	size_t			hctd_length,
	ohci_td_t		*td)
{
	uint32_t	page_addr, start_addr = 0, end_addr = 0;
	size_t		buf_len = hctd_length;
	int		rem_len, i;

	/*
	 * TDs must be filled in increasing DMA offset order.
	 * tw_dma_offs is initialized to be 0 at TW creation and
	 * is only increased in this function.
	 */
	ASSERT(buf_len == 0 || hctd_dma_offs >= tw->tw_dma_offs);

	Set_TD(td->hctd_xfer_offs, hctd_dma_offs);
	Set_TD(td->hctd_xfer_len, buf_len);

	/* Computing the starting buffer address and end buffer address */
	for (i = 0; (i < 2) && (buf_len > 0); i++) {
		/* Advance to the next DMA cookie if necessary */
		if ((tw->tw_dma_offs + tw->tw_cookie.dmac_size) <=
		    hctd_dma_offs) {
			/*
			 * tw_dma_offs always points to the starting offset
			 * of a cookie
			 */
			tw->tw_dma_offs += tw->tw_cookie.dmac_size;
			ddi_dma_nextcookie(tw->tw_dmahandle, &tw->tw_cookie);
			tw->tw_cookie_idx++;
			ASSERT(tw->tw_cookie_idx < tw->tw_ncookies);
		}

		ASSERT((tw->tw_dma_offs + tw->tw_cookie.dmac_size) >
		    hctd_dma_offs);

		/*
		 * Counting the remained buffer length to be filled in
		 * the TD for current DMA cookie
		 */
		rem_len = (tw->tw_dma_offs + tw->tw_cookie.dmac_size) -
		    hctd_dma_offs;

		/* Get the beginning address of the buffer */
		page_addr = (hctd_dma_offs - tw->tw_dma_offs) +
		    tw->tw_cookie.dmac_address;
		ASSERT((page_addr % OHCI_4K_ALIGN) == 0);

		if (i == 0) {
			start_addr = page_addr;
		}

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_init_td: page_addr 0x%x dmac_size "
		    "0x%lx idx %d", page_addr, tw->tw_cookie.dmac_size,
		    tw->tw_cookie_idx);

		if (buf_len <= OHCI_MAX_TD_BUF_SIZE) {
			ASSERT(buf_len <= rem_len);
			end_addr = page_addr + buf_len - 1;
			buf_len = 0;
			break;
		} else {
			ASSERT(rem_len >= OHCI_MAX_TD_BUF_SIZE);
			buf_len -= OHCI_MAX_TD_BUF_SIZE;
			hctd_dma_offs += OHCI_MAX_TD_BUF_SIZE;
		}
	}

	ASSERT(buf_len == 0);

	Set_TD(td->hctd_cbp, start_addr);
	Set_TD(td->hctd_buf_end, end_addr);
}


/*
 * ohci_init_itd:
 *
 * Initialize the buffer address portion of isoc Transfer Descriptor (TD).
 */
static void
ohci_init_itd(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw,
	uint_t			hctd_ctrl,
	uint32_t		index,
	ohci_td_t		*td)
{
	uint32_t		start_addr, end_addr, offset, offset_addr;
	ohci_isoc_buf_t		*bufp;
	size_t			buf_len;
	uint_t			buf, fc, toggle, flag;
	usb_isoc_pkt_descr_t	*temp_pkt_descr;
	int			i;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_init_itd: ctrl = 0x%x", hctd_ctrl);

	/*
	 * Write control information except starting
	 * usb frame number.
	 */
	Set_TD(td->hctd_ctrl, (hctd_ctrl | HC_TD_CC_NA));

	bufp = &tw->tw_isoc_bufs[index];
	Set_TD(td->hctd_xfer_offs, index);
	Set_TD(td->hctd_xfer_len, bufp->length);

	start_addr = bufp->cookie.dmac_address;
	ASSERT((start_addr % OHCI_4K_ALIGN) == 0);

	buf_len = bufp->length;
	if (bufp->ncookies == OHCI_DMA_ATTR_TD_SGLLEN) {
		buf_len = bufp->length - bufp->cookie.dmac_size;
		ddi_dma_nextcookie(bufp->dma_handle, &bufp->cookie);
	}
	end_addr = bufp->cookie.dmac_address + buf_len - 1;

	/*
	 * For an isochronous transfer, the hctd_cbp contains,
	 * the 4k page, and not the actual start of the buffer.
	 */
	Set_TD(td->hctd_cbp, ((uint32_t)start_addr & HC_ITD_PAGE_MASK));
	Set_TD(td->hctd_buf_end, end_addr);

	fc = (hctd_ctrl & HC_ITD_FC) >> HC_ITD_FC_SHIFT;
	toggle = 0;
	buf = start_addr;

	/*
	 * Get the address of first isochronous data packet
	 * for the current isochronous TD.
	 */
	temp_pkt_descr =  tw->tw_curr_isoc_pktp;

	/* The offsets are actually offsets into the page */
	for (i = 0; i <= fc; i++) {
		offset_addr = (uint32_t)((buf &
		    HC_ITD_OFFSET_ADDR) | (HC_ITD_OFFSET_CC));

		flag =	((start_addr &
		    HC_ITD_PAGE_MASK) ^ (buf & HC_ITD_PAGE_MASK));

		if (flag) {
			offset_addr |= HC_ITD_4KBOUNDARY_CROSS;
		}

		if (toggle) {
			offset = (uint32_t)((offset_addr <<
			    HC_ITD_OFFSET_SHIFT) & HC_ITD_ODD_OFFSET);

			Set_TD(td->hctd_offsets[i / 2],
			    Get_TD(td->hctd_offsets[i / 2]) | offset);
			toggle = 0;
		} else {
			offset = (uint32_t)(offset_addr & HC_ITD_EVEN_OFFSET);

			Set_TD(td->hctd_offsets[i / 2],
			    Get_TD(td->hctd_offsets[i / 2]) | offset);
			toggle = 1;
		}

		buf = (uint32_t)(buf + temp_pkt_descr->isoc_pkt_length);
		temp_pkt_descr++;
	}
}


/*
 * ohci_insert_td_with_frame_number:
 *
 * Insert current isochronous TD into the ED's list. with proper
 * usb frame number in which this TD can be processed.
 */
static int
ohci_insert_td_with_frame_number(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*current_td,
	ohci_td_t		*dummy_td)
{
	usb_isoc_req_t		*isoc_reqp =
	    (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;
	usb_frame_number_t	current_frame_number, start_frame_number;
	uint_t			ddic, ctrl, isoc_pkts;
	ohci_ed_t		*ept = pp->pp_ept;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_td_with_frame_number:"
	    "isoc flags 0x%x", isoc_reqp->isoc_attributes);

	/* Get the TD ctrl information */
	isoc_pkts = ((Get_TD(current_td->hctd_ctrl) &
	    HC_ITD_FC) >> HC_ITD_FC_SHIFT) + 1;

	/*
	 * Enter critical, while programming the usb frame number
	 * and inserting current isochronous TD into the ED's list.
	 */
	ddic = ddi_enter_critical();

	/* Get the current frame number */
	current_frame_number = ohci_get_current_frame_number(ohcip);

	/* Check the given isochronous flags */
	switch (isoc_reqp->isoc_attributes &
	    (USB_ATTRS_ISOC_START_FRAME | USB_ATTRS_ISOC_XFER_ASAP)) {
	case USB_ATTRS_ISOC_START_FRAME:
		/* Starting frame number is specified */
		if (pp->pp_flag & OHCI_ISOC_XFER_CONTINUE) {
			/* Get the starting usb frame number */
			start_frame_number = pp->pp_next_frame_number;
		} else {
			/* Check for the Starting usb frame number */
			if ((isoc_reqp->isoc_frame_no == 0) ||
			    ((isoc_reqp->isoc_frame_no +
			    isoc_reqp->isoc_pkts_count) <
			    current_frame_number)) {

				/* Exit the critical */
				ddi_exit_critical(ddic);

				USB_DPRINTF_L2(PRINT_MASK_LISTS,
				    ohcip->ohci_log_hdl,
				    "ohci_insert_td_with_frame_number:"
				    "Invalid starting frame number");

				return (USB_INVALID_START_FRAME);
			}

			/* Get the starting usb frame number */
			start_frame_number = isoc_reqp->isoc_frame_no;

			pp->pp_next_frame_number = 0;
		}
		break;
	case USB_ATTRS_ISOC_XFER_ASAP:
		/* ohci has to specify starting frame number */
		if ((pp->pp_next_frame_number) &&
		    (pp->pp_next_frame_number > current_frame_number)) {
			/*
			 * Get the next usb frame number.
			 */
			start_frame_number = pp->pp_next_frame_number;
		} else {
			/*
			 * Add appropriate offset to the current usb
			 * frame number and use it as a starting frame
			 * number.
			 */
			start_frame_number =
			    current_frame_number + OHCI_FRAME_OFFSET;
		}

		if (!(pp->pp_flag & OHCI_ISOC_XFER_CONTINUE)) {
			isoc_reqp->isoc_frame_no = start_frame_number;
		}
		break;
	default:
		/* Exit the critical */
		ddi_exit_critical(ddic);

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_insert_td_with_frame_number: Either starting "
		    "frame number or ASAP flags are not set, attrs = 0x%x",
		    isoc_reqp->isoc_attributes);

		return (USB_NO_FRAME_NUMBER);
	}

	/* Get the TD ctrl information */
	ctrl = Get_TD(current_td->hctd_ctrl) & (~(HC_ITD_SF));

	/* Set the frame number field */
	Set_TD(current_td->hctd_ctrl, ctrl | (start_frame_number & HC_ITD_SF));

	/*
	 * Add the new dummy to the ED's list. When this occurs,
	 * the Host Controller will see newly filled in dummy TD.
	 */
	Set_ED(ept->hced_tailp, (ohci_td_cpu_to_iommu(ohcip, dummy_td)));

	/* Exit the critical */
	ddi_exit_critical(ddic);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_insert_td_with_frame_number:"
	    "current frame number 0x%llx start frame number 0x%llx",
	    (unsigned long long)current_frame_number,
	    (unsigned long long)start_frame_number);

	/*
	 * Increment this saved frame number by current number
	 * of data packets needs to be transfer.
	 */
	pp->pp_next_frame_number = start_frame_number + isoc_pkts;

	/*
	 * Set OHCI_ISOC_XFER_CONTINUE flag in order to send other
	 * isochronous packets,  part of the current isoch request
	 * in the subsequent frames.
	 */
	pp->pp_flag |= OHCI_ISOC_XFER_CONTINUE;

	return (USB_SUCCESS);
}


/*
 * ohci_insert_td_on_tw:
 *
 * The transfer wrapper keeps a list of all Transfer Descriptors (TD) that
 * are allocated for this transfer. Insert a TD  onto this list. The  list
 * of TD's does not include the dummy TD that is at the end of the list of
 * TD's for the endpoint.
 */
static void
ohci_insert_td_on_tw(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td)
{
	/*
	 * Set the next pointer to NULL because
	 * this is the last TD on list.
	 */
	Set_TD(td->hctd_tw_next_td, NULL);

	if (tw->tw_hctd_head == NULL) {
		ASSERT(tw->tw_hctd_tail == NULL);
		tw->tw_hctd_head = td;
		tw->tw_hctd_tail = td;
	} else {
		ohci_td_t *dummy = (ohci_td_t *)tw->tw_hctd_tail;

		ASSERT(dummy != NULL);
		ASSERT(dummy != td);
		ASSERT(Get_TD(td->hctd_state) != HC_TD_DUMMY);

		/* Add the td to the end of the list */
		Set_TD(dummy->hctd_tw_next_td,
		    ohci_td_cpu_to_iommu(ohcip, td));

		tw->tw_hctd_tail = td;

		ASSERT(Get_TD(td->hctd_tw_next_td) == NULL);
	}
}


/*
 * ohci_traverse_tds:
 * NOTE: This function is also called from POLLED MODE.
 *
 * Traverse the list of TD's for an endpoint.  Since the endpoint is marked
 * as sKipped,	the Host Controller (HC) is no longer accessing these TD's.
 * Remove all the TD's that are attached to the endpoint.
 */
void
ohci_traverse_tds(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_trans_wrapper_t	*tw;
	ohci_ed_t		*ept;
	ohci_pipe_private_t	*pp;
	uint32_t		addr;
	ohci_td_t		*tailp, *headp, *next;

	pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	ept = pp->pp_ept;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: ph = 0x%p ept = 0x%p",
	    (void *)ph, (void *)ept);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	addr = Get_ED(ept->hced_headp) & (uint32_t)HC_EPT_TD_HEAD;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: addr (head) = 0x%x", addr);

	headp = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip, addr));

	addr = Get_ED(ept->hced_tailp) & (uint32_t)HC_EPT_TD_TAIL;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: addr (tail) = 0x%x", addr);

	tailp = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip, addr));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: cpu head = 0x%p cpu tail = 0x%p",
	    (void *)headp, (void *)tailp);

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: iommu head = 0x%x iommu tail = 0x%x",
	    ohci_td_cpu_to_iommu(ohcip, headp),
	    ohci_td_cpu_to_iommu(ohcip, tailp));

	/*
	 * Traverse the list of TD's that are currently on the endpoint.
	 * These TD's have not been processed and will not be processed
	 * because the endpoint processing is stopped.
	 */
	while (headp != tailp) {
		next = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip,
		    (Get_TD(headp->hctd_next_td) & HC_EPT_TD_TAIL)));

		tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID(
		    (uint32_t)Get_TD(headp->hctd_trans_wrapper));

		/* Stop the the transfer timer */
		ohci_stop_xfer_timer(ohcip, tw, OHCI_REMOVE_XFER_ALWAYS);

		ohci_deallocate_td(ohcip, headp);
		headp = next;
	}

	/* Both head and tail pointers must be same */
	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: head = 0x%p tail = 0x%p",
	    (void *)headp, (void *)tailp);

	/* Update the pointer in the endpoint descriptor */
	Set_ED(ept->hced_headp, (ohci_td_cpu_to_iommu(ohcip, headp)));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: new head = 0x%x",
	    (ohci_td_cpu_to_iommu(ohcip, headp)));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_traverse_tds: tailp = 0x%x headp = 0x%x",
	    (Get_ED(ept->hced_tailp) & HC_EPT_TD_TAIL),
	    (Get_ED(ept->hced_headp) & HC_EPT_TD_HEAD));

	ASSERT((Get_ED(ept->hced_tailp) & HC_EPT_TD_TAIL) ==
	    (Get_ED(ept->hced_headp) & HC_EPT_TD_HEAD));
}


/*
 * ohci_done_list_tds:
 *
 * There may be TD's on the done list that have not been processed yet. Walk
 * through these TD's and mark them as RECLAIM. All the mappings for the  TD
 * will be torn down, so the interrupt handle is alerted of this fact through
 * the RECLAIM flag.
 */
static void
ohci_done_list_tds(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	ohci_trans_wrapper_t	*head_tw = pp->pp_tw_head;
	ohci_trans_wrapper_t	*next_tw;
	ohci_td_t		*head_td, *next_td;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_done_list_tds:");

	/* Process the transfer wrappers for this pipe */
	next_tw = head_tw;
	while (next_tw) {
		head_td = (ohci_td_t *)next_tw->tw_hctd_head;
		next_td = head_td;

		if (head_td) {
			/*
			 * Walk through each TD for this transfer
			 * wrapper. If a TD still exists, then it
			 * is currently on the done list.
			 */
			while (next_td) {

				/* To free TD, set TD state to RECLAIM */
				Set_TD(next_td->hctd_state, HC_TD_RECLAIM);

				Set_TD(next_td->hctd_trans_wrapper, NULL);

				next_td = ohci_td_iommu_to_cpu(ohcip,
				    Get_TD(next_td->hctd_tw_next_td));
			}
		}

		/* Stop the the transfer timer */
		ohci_stop_xfer_timer(ohcip, next_tw, OHCI_REMOVE_XFER_ALWAYS);

		next_tw = next_tw->tw_next;
	}
}


/*
 * Remove old_td from tw and update the links.
 */
void
ohci_unlink_td_from_tw(
	ohci_state_t		*ohcip,
	ohci_td_t		*old_td,
	ohci_trans_wrapper_t	*tw)
{
	ohci_td_t *next, *head, *tail;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_unlink_td_from_tw: ohcip = 0x%p, old_td = 0x%p, tw = 0x%p",
	    (void *)ohcip, (void *)old_td, (void *)tw);

	if (old_td == NULL || tw == NULL) {

		return;
	}

	head = tw->tw_hctd_head;
	tail = tw->tw_hctd_tail;

	if (head == NULL) {

		return;
	}

	/* if this old_td is on head */
	if (old_td == head) {
		if (old_td == tail) {
			tw->tw_hctd_head = NULL;
			tw->tw_hctd_tail = NULL;
		} else {
			tw->tw_hctd_head = ohci_td_iommu_to_cpu(ohcip,
			    Get_TD(head->hctd_tw_next_td));
		}

		return;
	}

	/* find this old_td's position in the tw */
	next = ohci_td_iommu_to_cpu(ohcip, Get_TD(head->hctd_tw_next_td));
	while (next && (old_td != next)) {
		head = next;
		next = ohci_td_iommu_to_cpu(ohcip,
		    Get_TD(next->hctd_tw_next_td));
	}

	/* unlink the found old_td from the tw */
	if (old_td == next) {
		Set_TD(head->hctd_tw_next_td, Get_TD(next->hctd_tw_next_td));
		if (old_td == tail) {
			tw->tw_hctd_tail = head;
		}
	}
}


/*
 * ohci_deallocate_td:
 * NOTE: This function is also called from POLLED MODE.
 *
 * Deallocate a Host Controller's (HC) Transfer Descriptor (TD).
 */
void
ohci_deallocate_td(
	ohci_state_t	*ohcip,
	ohci_td_t	*old_td)
{
	ohci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_deallocate_td: old_td = 0x%p", (void *)old_td);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Obtain the transaction wrapper and tw will be
	 * NULL for the dummy and for the reclaim TD's.
	 */
	if ((Get_TD(old_td->hctd_state) == HC_TD_DUMMY) ||
	    (Get_TD(old_td->hctd_state) == HC_TD_RECLAIM)) {
		tw = (ohci_trans_wrapper_t *)((uintptr_t)
		    Get_TD(old_td->hctd_trans_wrapper));
		ASSERT(tw == NULL);
	} else {
		tw = (ohci_trans_wrapper_t *)
		    OHCI_LOOKUP_ID((uint32_t)
		    Get_TD(old_td->hctd_trans_wrapper));
		ASSERT(tw != NULL);
	}

	/*
	 * If this TD should be reclaimed, don't try to access its
	 * transfer wrapper.
	 */
	if ((Get_TD(old_td->hctd_state) != HC_TD_RECLAIM) && tw) {

		ohci_unlink_td_from_tw(ohcip, old_td, tw);
	}

	bzero((void *)old_td, sizeof (ohci_td_t));
	Set_TD(old_td->hctd_state, HC_TD_FREE);

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_deallocate_td: td 0x%p", (void *)old_td);
}


/*
 * ohci_td_cpu_to_iommu:
 * NOTE: This function is also called from POLLED MODE.
 *
 * This function converts for the given Transfer Descriptor (TD) CPU address
 * to IO address.
 */
uint32_t
ohci_td_cpu_to_iommu(
	ohci_state_t	*ohcip,
	ohci_td_t	*addr)
{
	uint32_t	td;

	td  = (uint32_t)ohcip->ohci_td_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr - (uintptr_t)(ohcip->ohci_td_pool_addr));

	ASSERT((ohcip->ohci_td_pool_cookie.dmac_address +
	    (uint32_t) (sizeof (ohci_td_t) *
	    (addr - ohcip->ohci_td_pool_addr))) ==
	    (ohcip->ohci_td_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr - (uintptr_t)
	    (ohcip->ohci_td_pool_addr))));

	ASSERT(td >= ohcip->ohci_td_pool_cookie.dmac_address);
	ASSERT(td <= ohcip->ohci_td_pool_cookie.dmac_address +
	    sizeof (ohci_td_t) * ohci_td_pool_size);

	return (td);
}


/*
 * ohci_td_iommu_to_cpu:
 * NOTE: This function is also called from POLLED MODE.
 *
 * This function converts for the given Transfer Descriptor (TD) IO address
 * to CPU address.
 */
ohci_td_t *
ohci_td_iommu_to_cpu(
	ohci_state_t	*ohcip,
	uintptr_t	addr)
{
	ohci_td_t	*td;

	if (addr == 0)
		return (NULL);

	td = (ohci_td_t *)((uintptr_t)
	    (addr - ohcip->ohci_td_pool_cookie.dmac_address) +
	    (uintptr_t)ohcip->ohci_td_pool_addr);

	ASSERT(td >= ohcip->ohci_td_pool_addr);
	ASSERT((uintptr_t)td <= (uintptr_t)ohcip->ohci_td_pool_addr +
	    (uintptr_t)(sizeof (ohci_td_t) * ohci_td_pool_size));

	return (td);
}

/*
 * ohci_allocate_tds_for_tw:
 *
 * Allocate n Transfer Descriptors (TD) from the TD buffer pool and places it
 * into the TW.
 *
 * Returns USB_NO_RESOURCES if it was not able to allocate all the requested TD
 * otherwise USB_SUCCESS.
 */
int
ohci_allocate_tds_for_tw(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw,
	size_t			td_count)
{
	ohci_td_t		*td;
	uint32_t		td_addr;
	int			i;
	int			error = USB_SUCCESS;

	for (i = 0; i < td_count; i++) {
		td = ohci_allocate_td_from_pool(ohcip);
		if (td == NULL) {
			error = USB_NO_RESOURCES;
			USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_allocate_tds_for_tw: "
			    "Unable to allocate %lu TDs",
			    td_count);
			break;
		}
		if (tw->tw_hctd_free_list != NULL) {
			td_addr = ohci_td_cpu_to_iommu(ohcip,
			    tw->tw_hctd_free_list);
			Set_TD(td->hctd_tw_next_td, td_addr);
		}
		tw->tw_hctd_free_list = td;
	}

	return (error);
}

/*
 * ohci_allocate_tw_resources:
 *
 * Allocate a Transaction Wrapper (TW) and n Transfer Descriptors (TD)
 * from the TD buffer pool and places it into the TW.  It does an all
 * or nothing transaction.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static ohci_trans_wrapper_t *
ohci_allocate_tw_resources(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	size_t			tw_length,
	usb_flags_t		usb_flags,
	size_t			td_count)
{
	ohci_trans_wrapper_t	*tw;

	tw = ohci_create_transfer_wrapper(ohcip, pp, tw_length, usb_flags);

	if (tw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_allocate_tw_resources: Unable to allocate TW");
	} else {
		if (ohci_allocate_tds_for_tw(ohcip, tw, td_count) ==
		    USB_SUCCESS) {
			tw->tw_num_tds = (uint_t)td_count;
		} else {
			ohci_deallocate_tw_resources(ohcip, pp, tw);
			tw = NULL;
		}
	}

	return (tw);
}

/*
 * ohci_free_tw_tds_resources:
 *
 * Free all allocated resources for Transaction Wrapper (TW).
 * Does not free the TW itself.
 */
static void
ohci_free_tw_tds_resources(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw)
{
	ohci_td_t		*td;
	ohci_td_t		*temp_td;

	td = tw->tw_hctd_free_list;
	while (td != NULL) {
		/* Save the pointer to the next td before destroying it */
		temp_td = ohci_td_iommu_to_cpu(ohcip,
		    Get_TD(td->hctd_tw_next_td));
		ohci_deallocate_td(ohcip, td);
		td = temp_td;
	}
	tw->tw_hctd_free_list = NULL;
}


/*
 * Transfer Wrapper functions
 *
 * ohci_create_transfer_wrapper:
 *
 * Create a Transaction Wrapper (TW) for non-isoc transfer types
 * and this involves the allocating of DMA resources.
 */
static ohci_trans_wrapper_t *
ohci_create_transfer_wrapper(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	size_t			length,
	uint_t			usb_flags)
{
	ddi_device_acc_attr_t	dev_attr;
	int			result;
	size_t			real_length;
	ohci_trans_wrapper_t	*tw;
	ddi_dma_attr_t		dma_attr;
	int			kmem_flag;
	int			(*dmamem_wait)(caddr_t);
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_create_transfer_wrapper: length = 0x%lx flags = 0x%x",
	    length, usb_flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* isochronous pipe should not call into this function */
	if ((ph->p_ep.bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_ISOCH) {

		return (NULL);
	}

	/* SLEEP flag should not be used while holding mutex */
	kmem_flag = KM_NOSLEEP;
	dmamem_wait = DDI_DMA_DONTWAIT;

	/* Allocate space for the transfer wrapper */
	tw = kmem_zalloc(sizeof (ohci_trans_wrapper_t), kmem_flag);

	if (tw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC,  ohcip->ohci_log_hdl,
		    "ohci_create_transfer_wrapper: kmem_zalloc failed");

		return (NULL);
	}

	/* zero-length packet doesn't need to allocate dma memory */
	if (length == 0) {

		goto dmadone;
	}

	/* allow sg lists for transfer wrapper dma memory */
	bcopy(&ohcip->ohci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = OHCI_DMA_ATTR_TW_SGLLEN;
	dma_attr.dma_attr_align = OHCI_DMA_ATTR_ALIGNMENT;

	/* Allocate the DMA handle */
	result = ddi_dma_alloc_handle(ohcip->ohci_dip,
	    &dma_attr, dmamem_wait, 0, &tw->tw_dmahandle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
		    "ohci_create_transfer_wrapper: Alloc handle failed");

		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (NULL);
	}

	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	/* The host controller will be little endian */
	dev_attr.devacc_attr_endian_flags  = DDI_STRUCTURE_BE_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Allocate the memory */
	result = ddi_dma_mem_alloc(tw->tw_dmahandle, length,
	    &dev_attr, DDI_DMA_CONSISTENT, dmamem_wait, NULL,
	    (caddr_t *)&tw->tw_buf, &real_length, &tw->tw_accesshandle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
		    "ohci_create_transfer_wrapper: dma_mem_alloc fail");

		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (NULL);
	}

	ASSERT(real_length >= length);

	/* Bind the handle */
	result = ddi_dma_addr_bind_handle(tw->tw_dmahandle, NULL,
	    (caddr_t)tw->tw_buf, real_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    dmamem_wait, NULL, &tw->tw_cookie, &tw->tw_ncookies);

	if (result != DDI_DMA_MAPPED) {
		ohci_decode_ddi_dma_addr_bind_handle_result(ohcip, result);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

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
	}

	/* Store the transfer length */
	tw->tw_length = length;

	/* Store a back pointer to the pipe private structure */
	tw->tw_pipe_private = pp;

	/* Store the transfer type - synchronous or asynchronous */
	tw->tw_flags = usb_flags;

	/* Get and Store 32bit ID */
	tw->tw_id = OHCI_GET_ID((void *)tw);

	ASSERT(tw->tw_id != NULL);

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_create_transfer_wrapper: tw = 0x%p, ncookies = %u",
	    (void *)tw, tw->tw_ncookies);

	return (tw);
}


/*
 * Transfer Wrapper functions
 *
 * ohci_create_isoc_transfer_wrapper:
 *
 * Create a Transaction Wrapper (TW) for isoc transfer
 * and this involves the allocating of DMA resources.
 */
static ohci_trans_wrapper_t *
ohci_create_isoc_transfer_wrapper(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	size_t			length,
	usb_isoc_pkt_descr_t	*descr,
	ushort_t		pkt_count,
	size_t			td_count,
	uint_t			usb_flags)
{
	ddi_device_acc_attr_t	dev_attr;
	int			result;
	size_t			real_length, xfer_size;
	uint_t			ccount;
	ohci_trans_wrapper_t	*tw;
	ddi_dma_attr_t		dma_attr;
	int			kmem_flag;
	uint_t			i, j, frame_count, residue;
	int			(*dmamem_wait)(caddr_t);
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_isoc_pkt_descr_t	*isoc_pkt_descr = descr;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_create_isoc_transfer_wrapper: length = 0x%lx flags = 0x%x",
	    length, usb_flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* non-isochronous pipe should not call into this function */
	if ((ph->p_ep.bmAttributes & USB_EP_ATTR_MASK) !=
	    USB_EP_ATTR_ISOCH) {

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
	tw = kmem_zalloc(sizeof (ohci_trans_wrapper_t), kmem_flag);

	if (tw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC,  ohcip->ohci_log_hdl,
		    "ohci_create_transfer_wrapper: kmem_zalloc failed");

		return (NULL);
	}

	/* Allocate space for the isoc buffer handles */
	tw->tw_isoc_strtlen = sizeof (ohci_isoc_buf_t) * td_count;
	if ((tw->tw_isoc_bufs = kmem_zalloc(tw->tw_isoc_strtlen,
	    kmem_flag)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS,  ohcip->ohci_log_hdl,
		    "ohci_create_isoc_transfer_wrapper: kmem_alloc "
		    "isoc buffer failed");
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (NULL);
	}

	/* allow sg lists for transfer wrapper dma memory */
	bcopy(&ohcip->ohci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = OHCI_DMA_ATTR_TD_SGLLEN;
	dma_attr.dma_attr_align = OHCI_DMA_ATTR_ALIGNMENT;

	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	/* The host controller will be little endian */
	dev_attr.devacc_attr_endian_flags  = DDI_STRUCTURE_BE_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	residue = pkt_count % OHCI_ISOC_PKTS_PER_TD;

	for (i = 0; i < td_count; i++) {
		tw->tw_isoc_bufs[i].index = i;

		if ((i == (td_count - 1)) && (residue != 0)) {
			frame_count = residue;
		} else {
			frame_count = OHCI_ISOC_PKTS_PER_TD;
		}

		/* Allocate the DMA handle */
		result = ddi_dma_alloc_handle(ohcip->ohci_dip, &dma_attr,
		    dmamem_wait, 0, &tw->tw_isoc_bufs[i].dma_handle);

		if (result != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
			    "ohci_create_isoc_transfer_wrapper: "
			    "Alloc handle failed");

			for (j = 0; j < i; j++) {
				result = ddi_dma_unbind_handle(
				    tw->tw_isoc_bufs[j].dma_handle);
				ASSERT(result == USB_SUCCESS);
				ddi_dma_mem_free(&tw->tw_isoc_bufs[j].
				    mem_handle);
				ddi_dma_free_handle(&tw->tw_isoc_bufs[j].
				    dma_handle);
			}
			kmem_free(tw->tw_isoc_bufs, tw->tw_isoc_strtlen);
			kmem_free(tw, sizeof (ohci_trans_wrapper_t));

			return (NULL);
		}

		/* Compute the memory length */
		for (xfer_size = 0, j = 0; j < frame_count; j++) {
			ASSERT(isoc_pkt_descr != NULL);
			xfer_size += isoc_pkt_descr->isoc_pkt_length;
			isoc_pkt_descr++;
		}

		/* Allocate the memory */
		result = ddi_dma_mem_alloc(tw->tw_isoc_bufs[i].dma_handle,
		    xfer_size, &dev_attr, DDI_DMA_CONSISTENT, dmamem_wait,
		    NULL, (caddr_t *)&tw->tw_isoc_bufs[i].buf_addr,
		    &real_length, &tw->tw_isoc_bufs[i].mem_handle);

		if (result != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
			    "ohci_create_isoc_transfer_wrapper: "
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
			kmem_free(tw->tw_isoc_bufs, tw->tw_isoc_strtlen);
			kmem_free(tw, sizeof (ohci_trans_wrapper_t));

			return (NULL);
		}

		ASSERT(real_length >= xfer_size);

		/* Bind the handle */
		result = ddi_dma_addr_bind_handle(
		    tw->tw_isoc_bufs[i].dma_handle, NULL,
		    (caddr_t)tw->tw_isoc_bufs[i].buf_addr, real_length,
		    DDI_DMA_RDWR|DDI_DMA_CONSISTENT, dmamem_wait, NULL,
		    &tw->tw_isoc_bufs[i].cookie, &ccount);

		if ((result == DDI_DMA_MAPPED) &&
		    (ccount <= OHCI_DMA_ATTR_TD_SGLLEN)) {
			tw->tw_isoc_bufs[i].length = xfer_size;
			tw->tw_isoc_bufs[i].ncookies = ccount;

			continue;
		} else {
			USB_DPRINTF_L2(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
			    "ohci_create_isoc_transfer_wrapper: "
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
			kmem_free(tw->tw_isoc_bufs, tw->tw_isoc_strtlen);
			kmem_free(tw, sizeof (ohci_trans_wrapper_t));

			return (NULL);
		}
	}

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
	}

	/* Store the transfer length */
	tw->tw_length = length;

	/* Store the td numbers */
	tw->tw_ncookies = (uint_t)td_count;

	/* Store a back pointer to the pipe private structure */
	tw->tw_pipe_private = pp;

	/* Store the transfer type - synchronous or asynchronous */
	tw->tw_flags = usb_flags;

	/* Get and Store 32bit ID */
	tw->tw_id = OHCI_GET_ID((void *)tw);

	ASSERT(tw->tw_id != NULL);

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_create_isoc_transfer_wrapper: tw = 0x%p", (void *)tw);

	return (tw);
}


/*
 * ohci_start_xfer_timer:
 *
 * Start the timer for the control, bulk and for one time interrupt
 * transfers.
 */
/* ARGSUSED */
static void
ohci_start_xfer_timer(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ohcip->ohci_log_hdl,
	    "ohci_start_xfer_timer: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * The timeout handling is done only for control, bulk and for
	 * one time Interrupt transfers.
	 *
	 * NOTE: If timeout is zero; Assume infinite timeout and don't
	 * insert this transfer on the timeout list.
	 */
	if (tw->tw_timeout) {
		/*
		 * Increase timeout value by one second and this extra one
		 * second is used to halt the endpoint if given transfer
		 * times out.
		 */
		tw->tw_timeout++;

		/*
		 * Add this transfer wrapper into the transfer timeout list.
		 */
		if (ohcip->ohci_timeout_list) {
			tw->tw_timeout_next = ohcip->ohci_timeout_list;
		}

		ohcip->ohci_timeout_list = tw;
		ohci_start_timer(ohcip);
	}
}


/*
 * ohci_stop_xfer_timer:
 *
 * Start the timer for the control, bulk and for one time interrupt
 * transfers.
 */
void
ohci_stop_xfer_timer(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw,
	uint_t			flag)
{
	timeout_id_t		timer_id;

	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ohcip->ohci_log_hdl,
	    "ohci_stop_xfer_timer: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * The timeout handling is done only for control, bulk
	 * and for one time Interrupt transfers.
	 */
	if (ohcip->ohci_timeout_list == NULL) {
		return;
	}

	switch (flag) {
	case OHCI_REMOVE_XFER_IFLAST:
		if (tw->tw_hctd_head != tw->tw_hctd_tail) {
			break;
		}
		/* FALLTHRU */
	case OHCI_REMOVE_XFER_ALWAYS:
		ohci_remove_tw_from_timeout_list(ohcip, tw);

		if ((ohcip->ohci_timeout_list == NULL) &&
		    (ohcip->ohci_timer_id)) {

			timer_id = ohcip->ohci_timer_id;

			/* Reset the timer id to zero */
			ohcip->ohci_timer_id = 0;

			mutex_exit(&ohcip->ohci_int_mutex);

			(void) untimeout(timer_id);

			mutex_enter(&ohcip->ohci_int_mutex);
		}
		break;
	default:
		break;
	}
}


/*
 * ohci_xfer_timeout_handler:
 *
 * Control or bulk transfer timeout handler.
 */
static void
ohci_xfer_timeout_handler(void *arg)
{
	ohci_state_t		*ohcip = (ohci_state_t *)arg;
	ohci_trans_wrapper_t	*exp_xfer_list_head = NULL;
	ohci_trans_wrapper_t	*exp_xfer_list_tail = NULL;
	ohci_trans_wrapper_t	*tw, *next;
	ohci_td_t		*td;
	usb_flags_t		flags;

	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ohcip->ohci_log_hdl,
	    "ohci_xfer_timeout_handler: ohcip = 0x%p", (void *)ohcip);

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Set the required flags */
	flags = OHCI_FLAGS_NOSLEEP | OHCI_FLAGS_DMA_SYNC;

	/*
	 * Check whether still timeout handler is valid.
	 */
	if (ohcip->ohci_timer_id) {

		/* Reset the timer id to zero */
		ohcip->ohci_timer_id = 0;
	} else {
		mutex_exit(&ohcip->ohci_int_mutex);

		return;
	}

	/* Get the transfer timeout list head */
	tw = ohcip->ohci_timeout_list;

	/*
	 * Process ohci timeout list and look whether the timer
	 * has expired for any transfers. Create a temporary list
	 * of expired transfers and process them later.
	 */
	while (tw) {
		/* Get the transfer on the timeout list */
		next = tw->tw_timeout_next;

		tw->tw_timeout--;

		/*
		 * Set the sKip bit to stop all transactions on
		 * this pipe
		 */
		if (tw->tw_timeout == 1) {
			ohci_modify_sKip_bit(ohcip,
			    tw->tw_pipe_private, SET_sKip, flags);

			/* Reset dma sync flag */
			flags &= ~OHCI_FLAGS_DMA_SYNC;
		}

		/* Remove tw from the timeout list */
		if (tw->tw_timeout == 0) {

			ohci_remove_tw_from_timeout_list(ohcip, tw);

			/* Add tw to the end of expire list */
			if (exp_xfer_list_head) {
				exp_xfer_list_tail->tw_timeout_next = tw;
			} else {
				exp_xfer_list_head = tw;
			}
			exp_xfer_list_tail = tw;
			tw->tw_timeout_next = NULL;
		}

		tw = next;
	}

	/* Get the expired transfer timeout list head */
	tw = exp_xfer_list_head;

	if (tw && (flags & OHCI_FLAGS_DMA_SYNC)) {
		/* Sync ED and TD pool */
		Sync_ED_TD_Pool(ohcip);
	}

	/*
	 * Process the expired transfers by notifing the corrsponding
	 * client driver through the exception callback.
	 */
	while (tw) {
		/* Get the transfer on the expired transfer timeout list */
		next = tw->tw_timeout_next;

		td = tw->tw_hctd_head;

		while (td) {
			/* Set TD state to TIMEOUT */
			Set_TD(td->hctd_state, HC_TD_TIMEOUT);

			/* Get the next TD from the wrapper */
			td = ohci_td_iommu_to_cpu(ohcip,
			    Get_TD(td->hctd_tw_next_td));
		}

		ohci_handle_error(ohcip, tw->tw_hctd_head, USB_CR_TIMEOUT);

		tw = next;
	}

	ohci_start_timer(ohcip);
	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_remove_tw_from_timeout_list:
 *
 * Remove Control or bulk transfer from the timeout list.
 */
static void
ohci_remove_tw_from_timeout_list(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw)
{
	ohci_trans_wrapper_t	*prev, *next;

	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ohcip->ohci_log_hdl,
	    "ohci_remove_tw_from_timeout_list: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	if (ohcip->ohci_timeout_list == tw) {
		ohcip->ohci_timeout_list = tw->tw_timeout_next;
	} else {
		prev = ohcip->ohci_timeout_list;
		next = prev->tw_timeout_next;

		while (next && (next != tw)) {
			prev = next;
			next = next->tw_timeout_next;
		}

		if (next == tw) {
			prev->tw_timeout_next = next->tw_timeout_next;
		}
	}

	/* Reset the xfer timeout */
	tw->tw_timeout_next = NULL;
}


/*
 * ohci_start_timer:
 *
 * Start the ohci timer
 */
static void
ohci_start_timer(ohci_state_t	*ohcip)
{
	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ohcip->ohci_log_hdl,
	    "ohci_start_timer: ohcip = 0x%p", (void *)ohcip);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Start the global timer only if currently timer is not
	 * running and if there are any transfers on the timeout
	 * list. This timer will be per USB Host Controller.
	 */
	if ((!ohcip->ohci_timer_id) && (ohcip->ohci_timeout_list)) {
		ohcip->ohci_timer_id = timeout(ohci_xfer_timeout_handler,
		    (void *)ohcip, drv_usectohz(1000000));
	}
}


/*
 * ohci_deallocate_tw_resources:
 * NOTE: This function is also called from POLLED MODE.
 *
 * Deallocate of a Transaction Wrapper (TW) and this involves the freeing of
 * of DMA resources.
 */
void
ohci_deallocate_tw_resources(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	ohci_trans_wrapper_t	*prev, *next;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_deallocate_tw_resources: tw = 0x%p", (void *)tw);

	/*
	 * If the transfer wrapper has no Host Controller (HC)
	 * Transfer Descriptors (TD) associated with it,  then
	 * remove the transfer wrapper.
	 */
	if (tw->tw_hctd_head) {
		ASSERT(tw->tw_hctd_tail != NULL);

		return;
	}

	ASSERT(tw->tw_hctd_tail == NULL);

	/* Make sure we return all the unused td's to the pool as well */
	ohci_free_tw_tds_resources(ohcip, tw);

	/*
	 * If pp->pp_tw_head and pp->pp_tw_tail are pointing to
	 * given TW then set the head and  tail  equal to NULL.
	 * Otherwise search for this TW in the linked TW's list
	 * and then remove this TW from the list.
	 */
	if (pp->pp_tw_head == tw) {
		if (pp->pp_tw_tail == tw) {
			pp->pp_tw_head = NULL;
			pp->pp_tw_tail = NULL;
		} else {
			pp->pp_tw_head = tw->tw_next;
		}
	} else {
		prev = pp->pp_tw_head;
		next = prev->tw_next;

		while (next && (next != tw)) {
			prev = next;
			next = next->tw_next;
		}

		if (next == tw) {
			prev->tw_next = next->tw_next;

			if (pp->pp_tw_tail == tw) {
				pp->pp_tw_tail = prev;
			}
		}
	}

	ohci_free_tw(ohcip, tw);
}


/*
 * ohci_free_dma_resources:
 *
 * Free dma resources of a Transfer Wrapper (TW) and also free the TW.
 */
static void
ohci_free_dma_resources(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	ohci_trans_wrapper_t	*head_tw = pp->pp_tw_head;
	ohci_trans_wrapper_t	*next_tw, *tw;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_free_dma_resources: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Process the Transfer Wrappers */
	next_tw = head_tw;
	while (next_tw) {
		tw = next_tw;
		next_tw = tw->tw_next;

		USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
		    "ohci_free_dma_resources: Free TW = 0x%p", (void *)tw);

		ohci_free_tw(ohcip, tw);
	}

	/* Adjust the head and tail pointers */
	pp->pp_tw_head = NULL;
	pp->pp_tw_tail = NULL;
}


/*
 * ohci_free_tw:
 *
 * Free the Transfer Wrapper (TW).
 */
static void
ohci_free_tw(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw)
{
	int			rval, i;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_free_tw: tw = 0x%p", (void *)tw);

	ASSERT(tw != NULL);
	ASSERT(tw->tw_id != NULL);

	/* Free 32bit ID */
	OHCI_FREE_ID((uint32_t)tw->tw_id);

	if (tw->tw_isoc_strtlen > 0) {
		ASSERT(tw->tw_isoc_bufs != NULL);
		for (i = 0; i < tw->tw_ncookies; i++) {
			if (tw->tw_isoc_bufs[i].ncookies > 0) {
				rval = ddi_dma_unbind_handle(
				    tw->tw_isoc_bufs[i].dma_handle);
				ASSERT(rval == USB_SUCCESS);
			}
			ddi_dma_mem_free(&tw->tw_isoc_bufs[i].mem_handle);
			ddi_dma_free_handle(&tw->tw_isoc_bufs[i].dma_handle);
		}
		kmem_free(tw->tw_isoc_bufs, tw->tw_isoc_strtlen);
	} else if (tw->tw_dmahandle != NULL) {
		if (tw->tw_ncookies > 0) {
			rval = ddi_dma_unbind_handle(tw->tw_dmahandle);
			ASSERT(rval == DDI_SUCCESS);
		}
		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
	}

	/* Free transfer wrapper */
	kmem_free(tw, sizeof (ohci_trans_wrapper_t));
}


/*
 * Interrupt Handling functions
 */

/*
 * ohci_intr:
 *
 * OpenHCI (OHCI) interrupt handling routine.
 */
static uint_t
ohci_intr(caddr_t arg1, caddr_t arg2)
{
	ohci_state_t		*ohcip = (ohci_state_t *)arg1;
	uint_t			intr;
	ohci_td_t		*done_head = NULL;
	ohci_save_intr_sts_t	*ohci_intr_sts = &ohcip->ohci_save_intr_sts;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_intr: Interrupt occurred, arg1 0x%p arg2 0x%p",
	    (void *)arg1, (void *)arg2);

	mutex_enter(&ohcip->ohci_int_mutex);

	/* Any interrupt is not handled for the suspended device. */
	if (ohcip->ohci_hc_soft_state == OHCI_CTLR_SUSPEND_STATE) {
		mutex_exit(&ohcip->ohci_int_mutex);

		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Suppose if we switched to the polled mode from the normal
	 * mode when interrupt handler is executing then we  need to
	 * save the interrupt status information in the  polled mode
	 * to  avoid race conditions. The following flag will be set
	 * and reset on entering & exiting of ohci interrupt handler
	 * respectively.  This flag will be used in the  polled mode
	 * to check whether the interrupt handler was running when we
	 * switched to the polled mode from the normal mode.
	 */
	ohci_intr_sts->ohci_intr_flag = OHCI_INTR_HANDLING;

	/* Temporarily turn off interrupts */
	Set_OpReg(hcr_intr_disable, HCR_INTR_MIE);

	/*
	 * Handle any missed ohci interrupt especially WriteDoneHead
	 * and SOF interrupts because of previous polled mode switch.
	 */
	ohci_handle_missed_intr(ohcip);

	/*
	 * Now process the actual ohci interrupt events  that caused
	 * invocation of this ohci interrupt handler.
	 */

	/*
	 * Updating the WriteDoneHead interrupt:
	 *
	 * (a) Host Controller
	 *
	 *	- First Host controller (HC) checks  whether WDH bit
	 *	  in the interrupt status register is cleared.
	 *
	 *	- If WDH bit is cleared then HC writes new done head
	 *	  list information into the HCCA done head field.
	 *
	 *	- Set WDH bit in the interrupt status register.
	 *
	 * (b) Host Controller Driver (HCD)
	 *
	 *	- First read the interrupt status register. The HCCA
	 *	  done head and WDH bit may be set or may not be set
	 *	  while reading the interrupt status register.
	 *
	 *	- Read the  HCCA done head list. By this time may be
	 *	  HC has updated HCCA done head and  WDH bit in ohci
	 *	  interrupt status register.
	 *
	 *	- If done head is non-null and if WDH bit is not set
	 *	  then Host Controller has updated HCCA  done head &
	 *	  WDH bit in the interrupt stats register in between
	 *	  reading the interrupt status register & HCCA	done
	 *	  head. In that case, definitely WDH bit will be set
	 *	  in the interrupt status register & driver can take
	 *	  it for granted.
	 *
	 * Now read the Interrupt Status & Interrupt enable register
	 * to determine the exact interrupt events.
	 */
	intr = ohci_intr_sts->ohci_curr_intr_sts =
	    (Get_OpReg(hcr_intr_status) & Get_OpReg(hcr_intr_enable));

	if (ohcip->ohci_hccap) {
		/* Sync HCCA area */
		Sync_HCCA(ohcip);

		/* Read and Save the HCCA DoneHead value */
		done_head = ohci_intr_sts->ohci_curr_done_lst =
		    (ohci_td_t *)(uintptr_t)
		    (Get_HCCA(ohcip->ohci_hccap->HccaDoneHead) &
		    HCCA_DONE_HEAD_MASK);

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Done head! 0x%p", (void *)done_head);
	}

	/* Update kstat values */
	ohci_do_intrs_stats(ohcip, intr);

	/*
	 * Look at the HccaDoneHead, if it is a non-zero valid address,
	 * a done list update interrupt is indicated. Otherwise, this
	 * intr bit is cleared.
	 */
	if (ohci_check_done_head(ohcip, done_head) == USB_SUCCESS) {

		/* Set the WriteDoneHead bit in the interrupt events */
		intr |= HCR_INTR_WDH;
	} else {

		/* Clear the WriteDoneHead bit */
		intr &= ~HCR_INTR_WDH;
	}

	/*
	 * We could have gotten a spurious interrupts. If so, do not
	 * claim it.  This is quite  possible on some  architectures
	 * where more than one PCI slots share the IRQs.  If so, the
	 * associated driver's interrupt routine may get called even
	 * if the interrupt is not meant for them.
	 *
	 * By unclaiming the interrupt, the other driver gets chance
	 * to service its interrupt.
	 */
	if (!intr) {

		/* Reset the interrupt handler flag */
		ohci_intr_sts->ohci_intr_flag &= ~OHCI_INTR_HANDLING;

		Set_OpReg(hcr_intr_enable, HCR_INTR_MIE);
		mutex_exit(&ohcip->ohci_int_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "Interrupt status 0x%x", intr);

	/*
	 * Check for Frame Number Overflow.
	 */
	if (intr & HCR_INTR_FNO) {
		USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Frame Number Overflow");

		ohci_handle_frame_number_overflow(ohcip);
	}

	if (intr & HCR_INTR_SOF) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Start of Frame");

		/* Set ohci_sof_flag indicating SOF interrupt occurred */
		ohcip->ohci_sof_flag = B_TRUE;

		/* Disabel SOF interrupt */
		Set_OpReg(hcr_intr_disable, HCR_INTR_SOF);

		/*
		 * Call cv_broadcast on every SOF interrupt to wakeup
		 * all the threads that are waiting the SOF.  Calling
		 * cv_broadcast on every SOF has no effect even if no
		 * threads are waiting for the SOF.
		 */
		cv_broadcast(&ohcip->ohci_SOF_cv);
	}

	if (intr & HCR_INTR_SO) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Schedule overrun");

		ohcip->ohci_so_error++;
	}

	if ((intr & HCR_INTR_WDH) && (done_head)) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Done Head");

		/*
		 * Currently if we are processing one  WriteDoneHead
		 * interrupt  and also if we  switched to the polled
		 * mode at least once  during this time,  then there
		 * may be chance that  Host Controller generates one
		 * more Write DoneHead or Start of Frame  interrupts
		 * for the normal since the polled code clears WDH &
		 * SOF interrupt bits before returning to the normal
		 * mode. Under this condition, we must not clear the
		 * HCCA done head field & also we must not clear WDH
		 * interrupt bit in the interrupt  status register.
		 */
		if (done_head == (ohci_td_t *)(uintptr_t)
		    (Get_HCCA(ohcip->ohci_hccap->HccaDoneHead) &
		    HCCA_DONE_HEAD_MASK)) {

			/* Reset the done head to NULL */
			Set_HCCA(ohcip->ohci_hccap->HccaDoneHead, 0);
		} else {
			intr &= ~HCR_INTR_WDH;
		}

		/* Clear the current done head field */
		ohci_intr_sts->ohci_curr_done_lst = NULL;

		ohci_traverse_done_list(ohcip, done_head);
	}

	/* Process endpoint reclaimation list */
	if (ohcip->ohci_reclaim_list) {
		ohci_handle_endpoint_reclaimation(ohcip);
	}

	if (intr & HCR_INTR_RD) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Resume Detected");
	}

	if (intr & HCR_INTR_RHSC) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Root hub status change");
	}

	if (intr & HCR_INTR_OC) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Change ownership");

	}

	if (intr & HCR_INTR_UE) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_intr: Unrecoverable error");

		ohci_handle_ue(ohcip);
	}

	/* Acknowledge the interrupt */
	Set_OpReg(hcr_intr_status, intr);

	/* Clear the current interrupt event field */
	ohci_intr_sts->ohci_curr_intr_sts = 0;

	/*
	 * Reset the following flag indicating exiting the interrupt
	 * handler and this flag will be used in the polled  mode to
	 * do some extra processing.
	 */
	ohci_intr_sts->ohci_intr_flag &= ~OHCI_INTR_HANDLING;

	Set_OpReg(hcr_intr_enable, HCR_INTR_MIE);

	/*
	 * Read interrupt status register to make sure that any PIO
	 * store to clear the ISR has made it on the PCI bus before
	 * returning from its interrupt handler.
	 */
	(void) Get_OpReg(hcr_intr_status);

	mutex_exit(&ohcip->ohci_int_mutex);

	USB_DPRINTF_L3(PRINT_MASK_INTR,  ohcip->ohci_log_hdl,
	    "Interrupt handling completed");

	return (DDI_INTR_CLAIMED);
}

/*
 * Check whether done_head is a valid td point address.
 * It should be non-zero, 16-byte aligned, and fall in ohci_td_pool.
 */
static int
ohci_check_done_head(ohci_state_t *ohcip, ohci_td_t *done_head)
{
	uintptr_t lower, upper, headp;
	lower = ohcip->ohci_td_pool_cookie.dmac_address;
	upper = lower + ohcip->ohci_td_pool_cookie.dmac_size;
	headp = (uintptr_t)done_head;

	if (headp && !(headp & ~HCCA_DONE_HEAD_MASK) &&
	    (headp >= lower) && (headp < upper)) {

		return (USB_SUCCESS);
	} else {

		return (USB_FAILURE);
	}
}

/*
 * ohci_handle_missed_intr:
 *
 * Handle any ohci missed interrupts because of polled mode switch.
 */
static void
ohci_handle_missed_intr(ohci_state_t	*ohcip)
{
	ohci_save_intr_sts_t		*ohci_intr_sts =
	    &ohcip->ohci_save_intr_sts;
	ohci_td_t			*done_head;
	uint_t				intr;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Check whether we have  missed any ohci interrupts because
	 * of the polled mode switch during  previous ohci interrupt
	 * handler execution. Only  Write Done Head & SOF interrupts
	 * saved in the polled mode. First process  these interrupts
	 * before processing actual interrupts that caused invocation
	 * of ohci interrupt handler.
	 */
	if (!ohci_intr_sts->ohci_missed_intr_sts) {
		/* No interrupts are missed, simply return */

		return;
	}

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_missed_intr: Handle ohci missed interrupts");

	/*
	 * The functionality and importance of critical code section
	 * in the normal mode ohci  interrupt handler & its usage in
	 * the polled mode is explained below.
	 *
	 * (a) Normal mode:
	 *
	 *	- Set the flag	indicating that  processing critical
	 *	  code in ohci interrupt handler.
	 *
	 *	- Process the missed ohci interrupts by  copying the
	 *	  miised interrupt events and done  head list fields
	 *	  information to the critical interrupt event & done
	 *	  list fields.
	 *
	 *	- Reset the missed ohci interrupt events & done head
	 *	  list fields so that the new missed interrupt event
	 *	  and done head list information can be saved.
	 *
	 *	- All above steps will be executed  with in critical
	 *	  section of the  interrupt handler.Then ohci missed
	 *	  interrupt handler will be called to service missed
	 *	  ohci interrupts.
	 *
	 * (b) Polled mode:
	 *
	 *	- On entering the polled code,it checks for critical
	 *	  section code execution within the normal mode ohci
	 *	  interrupt handler.
	 *
	 *	- If the critical section code is executing in normal
	 *	  mode ohci interrupt handler and if copying of ohci
	 *	  missed interrupt events & done head list fields to
	 *	  the critical fields is finished then save the "any
	 *	  missed interrupt events & done head list"  because
	 *	  of current polled mode switch into "critical missed
	 *	  interrupt events & done list fields" instead actual
	 *	  missed events and done list fields.
	 *
	 *	- Otherwise save "any missed interrupt events & done
	 *	  list" because of this  current polled  mode switch
	 *	  in the actual missed	interrupt events & done head
	 *	  list fields.
	 */

	/*
	 * Set flag indicating that  interrupt handler is processing
	 * critical interrupt code,  so that polled mode code checks
	 * for this condition & will do extra processing as explained
	 * above in order to aviod the race conditions.
	 */
	ohci_intr_sts->ohci_intr_flag |= OHCI_INTR_CRITICAL;
	ohci_intr_sts->ohci_critical_intr_sts |=
	    ohci_intr_sts->ohci_missed_intr_sts;

	if (ohci_intr_sts->ohci_missed_done_lst) {

		ohci_intr_sts->ohci_critical_done_lst =
		    ohci_intr_sts->ohci_missed_done_lst;
	}

	ohci_intr_sts->ohci_missed_intr_sts = 0;
	ohci_intr_sts->ohci_missed_done_lst = NULL;
	ohci_intr_sts->ohci_intr_flag &= ~OHCI_INTR_CRITICAL;

	intr = ohci_intr_sts->ohci_critical_intr_sts;
	done_head = ohci_intr_sts->ohci_critical_done_lst;

	if (intr & HCR_INTR_SOF) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_missed_intr: Start of Frame");

		/*
		 * Call cv_broadcast on every SOF interrupt to wakeup
		 * all the threads that are waiting the SOF.  Calling
		 * cv_broadcast on every SOF has no effect even if no
		 * threads are waiting for the SOF.
		 */
		cv_broadcast(&ohcip->ohci_SOF_cv);
	}

	if ((intr & HCR_INTR_WDH) && (done_head)) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_missed_intr: Done Head");

		/* Clear the critical done head field */
		ohci_intr_sts->ohci_critical_done_lst = NULL;

		ohci_traverse_done_list(ohcip, done_head);
	}

	/* Clear the critical interrupt event field */
	ohci_intr_sts->ohci_critical_intr_sts = 0;
}


/*
 * ohci_handle_ue:
 *
 * Handling of Unrecoverable Error interrupt (UE).
 */
static void
ohci_handle_ue(ohci_state_t	*ohcip)
{
	usb_frame_number_t	before_frame_number, after_frame_number;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_ue: Handling of UE interrupt");

	/*
	 * First check whether current UE error occured due to USB or
	 * due to some other subsystem. This can be verified by reading
	 * usb frame numbers before & after a delay of few milliseconds.
	 * If usb frame number read after delay is greater than the one
	 * read before delay, then, USB subsystem is fine. In this case,
	 * disable UE error interrupt and return without shutdowning the
	 * USB subsystem.
	 *
	 * Otherwise, if usb frame number read after delay is less than
	 * or equal to one read before the delay, then, current UE error
	 * occured from USB susbsystem. In this case,go ahead with actual
	 * UE error recovery procedure.
	 *
	 * Get the current usb frame number before waiting for few
	 * milliseconds.
	 */
	before_frame_number = ohci_get_current_frame_number(ohcip);

	/* Wait for few milliseconds */
	drv_usecwait(OHCI_TIMEWAIT);

	/*
	 * Get the current usb frame number after waiting for
	 * milliseconds.
	 */
	after_frame_number = ohci_get_current_frame_number(ohcip);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_ue: Before Frm No 0x%llx After Frm No 0x%llx",
	    (unsigned long long)before_frame_number,
	    (unsigned long long)after_frame_number);

	if (after_frame_number > before_frame_number) {

		/* Disable UE interrupt */
		Set_OpReg(hcr_intr_disable, HCR_INTR_UE);

		return;
	}

	/*
	 * This UE is due to USB hardware error. Reset ohci controller
	 * and reprogram to bring it back to functional state.
	 */
	if ((ohci_do_soft_reset(ohcip)) != USB_SUCCESS) {
		USB_DPRINTF_L0(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "Unrecoverable USB Hardware Error");

		/* Disable UE interrupt */
		Set_OpReg(hcr_intr_disable, HCR_INTR_UE);

		/* Set host controller soft state to error */
		ohcip->ohci_hc_soft_state = OHCI_CTLR_ERROR_STATE;
	}
}


/*
 * ohci_handle_frame_number_overflow:
 *
 * Update software based usb frame number part on every frame number
 * overflow interrupt.
 *
 * NOTE: This function is also called from POLLED MODE.
 *
 * Refer ohci spec 1.0a, section 5.3, page 81 for more details.
 */
void
ohci_handle_frame_number_overflow(ohci_state_t *ohcip)
{
	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_frame_number_overflow:");

	ohcip->ohci_fno += (0x10000 -
	    (((Get_HCCA(ohcip->ohci_hccap->HccaFrameNo) &
	    0xFFFF) ^ ohcip->ohci_fno) & 0x8000));

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_frame_number_overflow:"
	    "Frame Number Higher Part 0x%llx\n",
	    (unsigned long long)(ohcip->ohci_fno));
}


/*
 * ohci_handle_endpoint_reclaimation:
 *
 * Reclamation of Host Controller (HC) Endpoint Descriptors (ED).
 */
static void
ohci_handle_endpoint_reclaimation(ohci_state_t	*ohcip)
{
	usb_frame_number_t	current_frame_number;
	usb_frame_number_t	endpoint_frame_number;
	ohci_ed_t		*reclaim_ed;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_endpoint_reclaimation:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	current_frame_number = ohci_get_current_frame_number(ohcip);

	/*
	 * Deallocate all Endpoint Descriptors (ED) which are on the
	 * reclaimation list. These ED's are already removed from the
	 * interrupt lattice tree.
	 */
	while (ohcip->ohci_reclaim_list) {
		reclaim_ed = ohcip->ohci_reclaim_list;

		endpoint_frame_number = (usb_frame_number_t)(uintptr_t)
		    (OHCI_LOOKUP_ID(Get_ED(reclaim_ed->hced_reclaim_frame)));

		USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_endpoint_reclaimation:"
		    "current frame number 0x%llx endpoint frame number 0x%llx",
		    (unsigned long long)current_frame_number,
		    (unsigned long long)endpoint_frame_number);

		/*
		 * Deallocate current endpoint only if endpoint's usb frame
		 * number is less than or equal to current usb frame number.
		 *
		 * If endpoint's usb frame number is greater than the current
		 * usb frame number, ignore rest of the endpoints in the list
		 * since rest of the endpoints are inserted into the reclaim
		 * list later than the current reclaim endpoint.
		 */
		if (endpoint_frame_number > current_frame_number) {
			break;
		}

		/* Get the next endpoint from the rec. list */
		ohcip->ohci_reclaim_list = ohci_ed_iommu_to_cpu(ohcip,
		    Get_ED(reclaim_ed->hced_reclaim_next));

		/* Free 32bit ID */
		OHCI_FREE_ID((uint32_t)Get_ED(reclaim_ed->hced_reclaim_frame));

		/* Deallocate the endpoint */
		ohci_deallocate_ed(ohcip, reclaim_ed);
	}
}


/*
 * ohci_traverse_done_list:
 */
static void
ohci_traverse_done_list(
	ohci_state_t		*ohcip,
	ohci_td_t		*head_done_list)
{
	uint_t			state;		/* TD state */
	ohci_td_t		*td, *old_td;	/* TD pointers */
	usb_cr_t		error;		/* Error from TD */
	ohci_trans_wrapper_t	*tw = NULL;	/* Transfer wrapper */
	ohci_pipe_private_t	*pp = NULL;	/* Pipe private field */

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_traverse_done_list:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Sync ED and TD pool */
	Sync_ED_TD_Pool(ohcip);

	/* Reverse the done list */
	td = ohci_reverse_done_list(ohcip, head_done_list);

	/* Traverse the list of transfer descriptors */
	while (td) {
		/* Check for TD state */
		state = Get_TD(td->hctd_state);

		USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_traverse_done_list:\n\t"
		    "td = 0x%p	state = 0x%x", (void *)td, state);

		/*
		 * Obtain the  transfer wrapper only  if the TD is
		 * not marked as RECLAIM.
		 *
		 * A TD that is marked as  RECLAIM has had its DMA
		 * mappings, ED, TD and pipe private structure are
		 * ripped down. Just deallocate this TD.
		 */
		if (state != HC_TD_RECLAIM) {

			tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID(
			    (uint32_t)Get_TD(td->hctd_trans_wrapper));

			ASSERT(tw != NULL);

			pp = tw->tw_pipe_private;

			USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "ohci_traverse_done_list: PP = 0x%p TW = 0x%p",
			    (void *)pp, (void *)tw);
		}

		/*
		 * Don't process the TD if its	state is marked as
		 * either RECLAIM or TIMEOUT.
		 *
		 * A TD that is marked as TIMEOUT has already been
		 * processed by TD timeout handler & client driver
		 * has been informed through exception callback.
		 */
		if ((state != HC_TD_RECLAIM) && (state != HC_TD_TIMEOUT)) {

			/* Look at the error status */
			error = ohci_parse_error(ohcip, td);

			if (error == USB_CR_OK) {
				ohci_handle_normal_td(ohcip, td, tw);
			} else {
				/* handle the error condition */
				ohci_handle_error(ohcip, td, error);
			}
		} else {
			USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "ohci_traverse_done_list: TD State = %d", state);
		}

		/*
		 * Save a pointer to the current transfer descriptor
		 */
		old_td = td;

		td = ohci_td_iommu_to_cpu(ohcip, Get_TD(td->hctd_next_td));

		/* Deallocate this transfer descriptor */
		ohci_deallocate_td(ohcip, old_td);

		/*
		 * Deallocate the transfer wrapper if there are no more
		 * TD's for the transfer wrapper. ohci_deallocate_tw_resources()
		 * will  not deallocate the tw for a periodic  endpoint
		 * since it will always have a TD attached to it.
		 *
		 * Do not deallocate the TW if it is a isoc or intr pipe in.
		 * The tw's are reused.
		 *
		 * An TD that is marked as reclaim doesn't have a  pipe
		 * or a TW associated with it anymore so don't call this
		 * function.
		 */
		if (state != HC_TD_RECLAIM) {
			ASSERT(tw != NULL);
			ohci_deallocate_tw_resources(ohcip, pp, tw);
		}
	}
}


/*
 * ohci_reverse_done_list:
 *
 * Reverse the order of the Transfer Descriptor (TD) Done List.
 */
static ohci_td_t *
ohci_reverse_done_list(
	ohci_state_t	*ohcip,
	ohci_td_t	*head_done_list)
{
	ohci_td_t	*cpu_new_tail, *cpu_new_head, *cpu_save;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_reverse_done_list:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));
	ASSERT(head_done_list != NULL);

	/* At first, both the tail and head pointers point to the same elem */
	cpu_new_tail = cpu_new_head =
	    ohci_td_iommu_to_cpu(ohcip, (uintptr_t)head_done_list);

	/* See if the list has only one element */
	if (Get_TD(cpu_new_head->hctd_next_td) == 0) {

		return (cpu_new_head);
	}

	/* Advance the head pointer */
	cpu_new_head = (ohci_td_t *)
	    ohci_td_iommu_to_cpu(ohcip, Get_TD(cpu_new_head->hctd_next_td));

	/* The new tail now points to nothing */
	Set_TD(cpu_new_tail->hctd_next_td, NULL);

	cpu_save = (ohci_td_t *)
	    ohci_td_iommu_to_cpu(ohcip, Get_TD(cpu_new_head->hctd_next_td));

	/* Reverse the list and store the pointers as CPU addresses */
	while (cpu_save) {
		Set_TD(cpu_new_head->hctd_next_td,
		    ohci_td_cpu_to_iommu(ohcip, cpu_new_tail));

		cpu_new_tail = cpu_new_head;
		cpu_new_head = cpu_save;

		cpu_save = (ohci_td_t *)
		    ohci_td_iommu_to_cpu(ohcip,
		    Get_TD(cpu_new_head->hctd_next_td));
	}

	Set_TD(cpu_new_head->hctd_next_td,
	    ohci_td_cpu_to_iommu(ohcip, cpu_new_tail));

	return (cpu_new_head);
}


/*
 * ohci_parse_error:
 *
 * Parse the result for any errors.
 */
static usb_cr_t
ohci_parse_error(
	ohci_state_t		*ohcip,
	ohci_td_t		*td)
{
	uint_t			ctrl;
	usb_ep_descr_t		*eptd;
	ohci_trans_wrapper_t	*tw;
	ohci_pipe_private_t	*pp;
	uint_t			flag;
	usb_cr_t		error;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_parse_error:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	ASSERT(td != NULL);

	/* Obtain the transfer wrapper from the TD */
	tw = (ohci_trans_wrapper_t *)
	    OHCI_LOOKUP_ID((uint32_t)Get_TD(td->hctd_trans_wrapper));

	ASSERT(tw != NULL);

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_parse_error: PP 0x%p TW 0x%p", (void *)pp, (void *)tw);

	eptd = &pp->pp_pipe_handle->p_ep;

	ctrl = (uint_t)Get_TD(td->hctd_ctrl) & (uint32_t)HC_TD_CC;

	/*
	 * Check the condition code of completed TD and report errors
	 * if any. This checking will be done both for the general and
	 * the isochronous TDs.
	 */
	if ((error = ohci_check_for_error(ohcip, pp, tw, td, ctrl)) !=
	    USB_CR_OK) {
		flag = OHCI_REMOVE_XFER_ALWAYS;
	} else {
		flag  = OHCI_REMOVE_XFER_IFLAST;
	}

	/* Stop the the transfer timer */
	ohci_stop_xfer_timer(ohcip, tw, flag);

	/*
	 * The isochronous endpoint needs additional error checking
	 * and special processing.
	 */
	if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_ISOCH) {

		ohci_parse_isoc_error(ohcip, pp, tw, td);

		/* always reset error */
		error = USB_CR_OK;
	}

	return (error);
}


/*
 * ohci_parse_isoc_error:
 *
 * Check for any errors in the isochronous data packets. Also fillup
 * the status for each of the isochrnous data packets.
 */
void
ohci_parse_isoc_error(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td)
{
	usb_isoc_req_t		*isoc_reqp;
	usb_isoc_pkt_descr_t	*isoc_pkt_descr;
	uint_t			toggle = 0, fc, ctrl, psw;
	int			i;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_parse_isoc_error: td 0x%p", (void *)td);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	fc = ((uint_t)Get_TD(td->hctd_ctrl) &
	    HC_ITD_FC) >> HC_ITD_FC_SHIFT;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_parse_isoc_error: frame count %d", fc);

	/*
	 * Get the address of current usb isochronous request
	 * and array of packet descriptors.
	 */
	isoc_reqp = (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;
	isoc_pkt_descr = isoc_reqp->isoc_pkt_descr;
	isoc_pkt_descr += tw->tw_pkt_idx;

	for (i = 0; i <= fc; i++) {

		psw = Get_TD(td->hctd_offsets[i / 2]);

		if (toggle) {
			ctrl = psw & HC_ITD_ODD_OFFSET;
			toggle = 0;
		} else {
			ctrl =	(psw & HC_ITD_EVEN_OFFSET) <<
			    HC_ITD_OFFSET_SHIFT;
			toggle = 1;
		}

		isoc_pkt_descr->isoc_pkt_actual_length =
		    (ctrl >> HC_ITD_OFFSET_SHIFT) & HC_ITD_OFFSET_ADDR;

		ctrl = (uint_t)(ctrl & (uint32_t)HC_TD_CC);

		/* Write the status of isoc data packet */
		isoc_pkt_descr->isoc_pkt_status =
		    ohci_check_for_error(ohcip, pp, tw, td, ctrl);

		if (isoc_pkt_descr->isoc_pkt_status) {
			/* Increment isoc data packet error count */
			isoc_reqp->isoc_error_count++;
		}

		/*
		 * Get the address of next isoc data packet descriptor.
		 */
		isoc_pkt_descr++;
	}
	tw->tw_pkt_idx = tw->tw_pkt_idx + fc + 1;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_parse_isoc_error: tw_pkt_idx %d", tw->tw_pkt_idx);

}


/*
 * ohci_check_for_error:
 *
 * Check for any errors.
 */
static usb_cr_t
ohci_check_for_error(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td,
	uint_t			ctrl)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uchar_t			ep_attrs = ph->p_ep.bmAttributes;
	usb_cr_t		error = USB_CR_OK;
	usb_req_attrs_t		xfer_attrs;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_check_for_error: td = 0x%p ctrl = 0x%x",
	    (void *)td, ctrl);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	switch (ctrl) {
	case HC_TD_CC_NO_E:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: No Error");
		error = USB_CR_OK;
		break;
	case HC_TD_CC_CRC:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: CRC error");
		error = USB_CR_CRC;
		break;
	case HC_TD_CC_BS:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Bit stuffing");
		error = USB_CR_BITSTUFFING;
		break;
	case HC_TD_CC_DTM:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Data Toggle Mismatch");
		error = USB_CR_DATA_TOGGLE_MM;
		break;
	case HC_TD_CC_STALL:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Stall");
		error = USB_CR_STALL;
		break;
	case HC_TD_CC_DNR:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Device not responding");
		error = USB_CR_DEV_NOT_RESP;
		break;
	case HC_TD_CC_PCF:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: PID check failure");
		error = USB_CR_PID_CHECKFAILURE;
		break;
	case HC_TD_CC_UPID:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Unexpected PID");
		error = USB_CR_UNEXP_PID;
		break;
	case HC_TD_CC_DO:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Data overrrun");
		error = USB_CR_DATA_OVERRUN;
		break;
	case HC_TD_CC_DU:
		/*
		 * Check whether short packets are acceptable.
		 * If so don't report error to client drivers
		 * and restart the endpoint. Otherwise report
		 * data underrun error to client driver.
		 */
		xfer_attrs = ohci_get_xfer_attrs(ohcip, pp, tw);

		if (xfer_attrs & USB_ATTRS_SHORT_XFER_OK) {
			error = USB_CR_OK;
			if ((ep_attrs & USB_EP_ATTR_MASK) !=
			    USB_EP_ATTR_ISOCH) {
				/*
				 * Cleanup the remaining resources that may have
				 * been allocated for this transfer.
				 */
				if (ohci_cleanup_data_underrun(ohcip, pp, tw,
				    td) == USB_SUCCESS) {
					/* Clear the halt bit */
					Set_ED(pp->pp_ept->hced_headp,
					    (Get_ED(pp->pp_ept->hced_headp) &
					    ~HC_EPT_Halt));
				} else {
					error = USB_CR_UNSPECIFIED_ERR;
				}
			}
		} else {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "ohci_check_for_error: Data underrun");

			error = USB_CR_DATA_UNDERRUN;
		}

		break;
	case HC_TD_CC_BO:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Buffer overrun");
		error = USB_CR_BUFFER_OVERRUN;
		break;
	case HC_TD_CC_BU:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Buffer underrun");
		error = USB_CR_BUFFER_UNDERRUN;
		break;
	case HC_TD_CC_NA:
	default:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Not accessed");
		error = USB_CR_NOT_ACCESSED;
		break;
	}

	if (error) {
		uint_t hced_ctrl =  Get_ED(pp->pp_ept->hced_ctrl);

		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_check_for_error: Error %d Device address %d "
		    "Endpoint number %d", error, (hced_ctrl & HC_EPT_FUNC),
		    ((hced_ctrl & HC_EPT_EP) >> HC_EPT_EP_SHFT));
	}

	return (error);
}


/*
 * ohci_handle_error:
 *
 * Inform USBA about occured transaction errors by calling the USBA callback
 * routine.
 */
static void
ohci_handle_error(
	ohci_state_t		*ohcip,
	ohci_td_t		*td,
	usb_cr_t		error)
{
	ohci_trans_wrapper_t	*tw;
	usba_pipe_handle_data_t	*ph;
	ohci_pipe_private_t	*pp;
	mblk_t			*mp = NULL;
	size_t			length = 0;
	uchar_t			attributes;
	usb_intr_req_t		*curr_intr_reqp;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_error: error = 0x%x", error);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	ASSERT(td != NULL);

	/* Print the values in the td */
	ohci_print_td(ohcip, td);

	/* Obtain the transfer wrapper from the TD */
	tw = (ohci_trans_wrapper_t *)
	    OHCI_LOOKUP_ID((uint32_t)Get_TD(td->hctd_trans_wrapper));

	ASSERT(tw != NULL);

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	ph = tw->tw_pipe_private->pp_pipe_handle;
	attributes = ph->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	/*
	 * Special error handling
	 */
	if (tw->tw_direction == HC_TD_IN) {

		switch (attributes) {
		case USB_EP_ATTR_CONTROL:
			if (((ph->p_ep.bmAttributes &
			    USB_EP_ATTR_MASK) ==
			    USB_EP_ATTR_CONTROL) &&
			    (Get_TD(td->hctd_ctrl_phase) ==
			    OHCI_CTRL_SETUP_PHASE)) {

				break;
			}
			/* FALLTHROUGH */
		case USB_EP_ATTR_BULK:
			/*
			 * Call ohci_sendup_td_message
			 * to send message to upstream.
			 */
			ohci_sendup_td_message(ohcip, pp, tw, td, error);

			return;
		case USB_EP_ATTR_INTR:
			curr_intr_reqp =
			    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

			if (curr_intr_reqp->intr_attributes &
			    USB_ATTRS_ONE_XFER) {

				ohci_handle_one_xfer_completion(ohcip, tw);
			}

			/* Decrement periodic in request count */
			pp->pp_cur_periodic_req_cnt--;
			break;
		case USB_EP_ATTR_ISOCH:
		default:
			break;
		}
	} else {
		switch (attributes) {
		case USB_EP_ATTR_BULK:
		case USB_EP_ATTR_INTR:
			/*
			 * If "CurrentBufferPointer" of Transfer
			 * Descriptor (TD) is not equal to zero,
			 * then we sent less data  to the device
			 * than requested by client. In that case,
			 * return the mblk after updating the
			 * data->r_ptr.
			 */
			if (Get_TD(td->hctd_cbp)) {
				usb_opaque_t xfer_reqp = tw->tw_curr_xfer_reqp;
				size_t residue;

				residue = ohci_get_td_residue(ohcip, td);
				length = Get_TD(td->hctd_xfer_offs) +
				    Get_TD(td->hctd_xfer_len) - residue;

				USB_DPRINTF_L2(PRINT_MASK_INTR,
				    ohcip->ohci_log_hdl,
				    "ohci_handle_error: requested data %lu "
				    "sent data %lu", tw->tw_length, length);

				if (attributes == USB_EP_ATTR_BULK) {
					mp = (mblk_t *)((usb_bulk_req_t *)
					    (xfer_reqp))->bulk_data;
				} else {
					mp = (mblk_t *)((usb_intr_req_t *)
					    (xfer_reqp))->intr_data;
				}

				/* Increment the read pointer */
				mp->b_rptr = mp->b_rptr + length;
			}
			break;
		default:
			break;
		}
	}

	/*
	 * Callback the client with the
	 * failure reason.
	 */
	ohci_hcdi_callback(ph, tw, error);

	/* Check anybody is waiting for transfers completion event */
	ohci_check_for_transfers_completion(ohcip, pp);
}

/*
 * ohci_cleanup_data_underrun:
 *
 * Cleans up resources when a short xfer occurs
 */
static int
ohci_cleanup_data_underrun(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td)
{
	ohci_td_t		*next_td;
	ohci_td_t		*last_td;
	ohci_td_t		*temp_td;
	uint32_t		last_td_addr;
	uint_t			hced_head;

	USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_cleanup_data_underrun: td 0x%p, tw 0x%p",
	    (void *)td, (void *)tw);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));
	ASSERT(tw->tw_hctd_head == td);

	/* Check if this TD is the last td in the tw */
	last_td = tw->tw_hctd_tail;
	if (td == last_td) {
		/* There is no need for cleanup */
		return (USB_SUCCESS);
	}

	/*
	 * Make sure the ED is halted before we change any td's.
	 * If for some reason it is not halted, return error to client
	 * driver so they can reset the port.
	 */
	hced_head = Get_ED(pp->pp_ept->hced_headp);
	if (!(hced_head & HC_EPT_Halt)) {
		uint_t hced_ctrl = Get_ED(pp->pp_ept->hced_ctrl);

		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_cleanup_data_underrun: Unable to clean up a short "
		    "xfer error.  Client might send/receive irrelevant data."
		    " Device address %d Endpoint number %d",
		    (hced_ctrl & HC_EPT_FUNC),
		    ((hced_ctrl & HC_EPT_EP) >> HC_EPT_EP_SHFT));

		Set_ED(pp->pp_ept->hced_headp, hced_head | HC_EPT_Halt);

		return (USB_FAILURE);
	}

	/*
	 * Get the address of the first td of the next transfer (tw).
	 * This td, may currently be a dummy td, but when a new request
	 * arrives, it will be transformed into a regular td.
	 */
	last_td_addr = Get_TD(last_td->hctd_next_td);
	/* Set ED head to this last td */
	Set_ED(pp->pp_ept->hced_headp,
	    (last_td_addr & HC_EPT_TD_HEAD) |
	    (hced_head & ~HC_EPT_TD_HEAD));

	/*
	 * Start removing all the unused TD's from the TW,
	 * but keep the first one.
	 */
	tw->tw_hctd_tail = td;

	/*
	 * Get the last_td, the next td in the tw list.
	 * Afterwards completely disassociate the current td from other tds
	 */
	next_td = (ohci_td_t *)ohci_td_iommu_to_cpu(ohcip,
	    Get_TD(td->hctd_tw_next_td));
	Set_TD(td->hctd_tw_next_td, NULL);

	/*
	 * Iterate down the tw list and deallocate them
	 */
	while (next_td != NULL) {
		tw->tw_num_tds--;
		/* Disassociate this td from it's TW and set to RECLAIM */
		Set_TD(next_td->hctd_trans_wrapper, NULL);
		Set_TD(next_td->hctd_state, HC_TD_RECLAIM);

		temp_td = next_td;

		next_td = (ohci_td_t *)ohci_td_iommu_to_cpu(ohcip,
		    Get_TD(next_td->hctd_tw_next_td));

		ohci_deallocate_td(ohcip, temp_td);
	}

	ASSERT(tw->tw_num_tds == 1);

	return (USB_SUCCESS);
}

/*
 * ohci_handle_normal_td:
 */
static void
ohci_handle_normal_td(
	ohci_state_t		*ohcip,
	ohci_td_t		*td,
	ohci_trans_wrapper_t	*tw)
{
	ohci_pipe_private_t	*pp;	/* Pipe private field */

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_normal_td:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));
	ASSERT(tw != NULL);

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	(*tw->tw_handle_td)(ohcip, pp, tw,
	    td, tw->tw_handle_callback_value);

	/* Check anybody is waiting for transfers completion event */
	ohci_check_for_transfers_completion(ohcip, pp);
}


/*
 * ohci_handle_ctrl_td:
 *
 * Handle a control Transfer Descriptor (TD).
 */
/* ARGSUSED */
static void
ohci_handle_ctrl_td(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td,
	void			*tw_handle_callback_value)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_ctrl_td: pp = 0x%p tw = 0x%p td = 0x%p state = 0x%x",
	    (void *)pp, (void *)tw, (void *)td, Get_TD(td->hctd_ctrl_phase));

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Check which control transfer phase got completed.
	 */
	tw->tw_num_tds--;
	switch (Get_TD(td->hctd_ctrl_phase)) {
	case OHCI_CTRL_SETUP_PHASE:
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "Setup complete: pp 0x%p td 0x%p", (void *)pp, (void *)td);

		break;
	case OHCI_CTRL_DATA_PHASE:
		/*
		 * If "CurrentBufferPointer" of Transfer Descriptor (TD)
		 * is not equal to zero, then we received less data from
		 * the device than requested by us. In that case, get the
		 * actual received data size.
		 */
		if (Get_TD(td->hctd_cbp)) {
			size_t			length, residue;

			residue = ohci_get_td_residue(ohcip, td);
			length = Get_TD(td->hctd_xfer_offs) +
			    Get_TD(td->hctd_xfer_len) - residue;

			USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "ohci_handle_ctrl_qtd: requested data %lu "
			    "received data %lu", tw->tw_length, length);

			/* Save actual received data length */
			tw->tw_length = length;
		}

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "Data complete: pp 0x%p td 0x%p",
		    (void *)pp, (void *)td);

		break;
	case OHCI_CTRL_STATUS_PHASE:
		if ((tw->tw_length != 0) &&
		    (tw->tw_direction == HC_TD_IN)) {

			/*
			 * Call ohci_sendup_td_message
			 * to send message to upstream.
			 */
			ohci_sendup_td_message(ohcip,
			    pp, tw, td, USB_CR_OK);
		} else {
			ohci_do_byte_stats(ohcip,
			    tw->tw_length - OHCI_MAX_TD_BUF_SIZE,
			    ph->p_ep.bmAttributes,
			    ph->p_ep.bEndpointAddress);

			ohci_hcdi_callback(ph, tw, USB_CR_OK);
		}

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "Status complete: pp 0x%p td 0x%p", (void *)pp, (void *)td);

		break;
	}
}


/*
 * ohci_handle_bulk_td:
 *
 * Handle a bulk Transfer Descriptor (TD).
 */
/* ARGSUSED */
static void
ohci_handle_bulk_td(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td,
	void			*tw_handle_callback_value)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_bulk_td:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Decrement the TDs counter and check whether all the bulk
	 * data has been send or received. If TDs counter reaches
	 * zero then inform client driver about completion current
	 * bulk request. Other wise wait for completion of other bulk
	 * TDs or transactions on this pipe.
	 */
	if (--tw->tw_num_tds != 0) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_bulk_td: Number of TDs %d", tw->tw_num_tds);

		return;
	}

	/*
	 * If this is a bulk in pipe, return the data to the client.
	 * For a bulk out pipe, there is no need to do anything.
	 */
	if ((eptd->bEndpointAddress &
	    USB_EP_DIR_MASK) == USB_EP_DIR_OUT) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_bulk_td: Bulk out pipe");

		ohci_do_byte_stats(ohcip, tw->tw_length,
		    eptd->bmAttributes, eptd->bEndpointAddress);

		/* Do the callback */
		ohci_hcdi_callback(ph, tw, USB_CR_OK);

		return;
	}

	/* Call ohci_sendup_td_message to send message to upstream */
	ohci_sendup_td_message(ohcip, pp, tw, td, USB_CR_OK);
}


/*
 * ohci_handle_intr_td:
 *
 * Handle a interrupt Transfer Descriptor (TD).
 */
/* ARGSUSED */
static void
ohci_handle_intr_td(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td,
	void			*tw_handle_callback_value)
{
	usb_intr_req_t		*curr_intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	usb_req_attrs_t		attrs;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_intr_td: pp=0x%p tw=0x%p td=0x%p"
	    "intr_reqp=0%p data=0x%p", (void *)pp, (void *)tw, (void *)td,
	    (void *)curr_intr_reqp, (void *)curr_intr_reqp->intr_data);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Get the interrupt xfer attributes */
	attrs = curr_intr_reqp->intr_attributes;

	/*
	 * For a Interrupt OUT pipe, we just callback and we are done
	 */
	if ((eptd->bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_OUT) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_intr_td: Intr out pipe, intr_reqp=0x%p,"
		    "data=0x%p", (void *)curr_intr_reqp,
		    (void *)curr_intr_reqp->intr_data);

		ohci_do_byte_stats(ohcip, tw->tw_length,
		    eptd->bmAttributes, eptd->bEndpointAddress);

		/* Do the callback */
		ohci_hcdi_callback(ph, tw, USB_CR_OK);

		return;
	}

	/* Decrement number of interrupt request count */
	pp->pp_cur_periodic_req_cnt--;

	/*
	 * Check usb flag whether USB_FLAGS_ONE_XFER flag is set
	 * and if so, free duplicate request.
	 */
	if (attrs & USB_ATTRS_ONE_XFER) {
		ohci_handle_one_xfer_completion(ohcip, tw);
	}

	/* Call ohci_sendup_td_message to callback into client */
	ohci_sendup_td_message(ohcip, pp, tw, td, USB_CR_OK);

	/*
	 * If interrupt pipe state is still active, insert next Interrupt
	 * request into the Host Controller's Interrupt list.  Otherwise
	 * you are done.
	 */
	if (pp->pp_state != OHCI_PIPE_STATE_ACTIVE) {
		return;
	}

	if ((error = ohci_allocate_periodic_in_resource(ohcip, pp, tw, 0)) ==
	    USB_SUCCESS) {
		curr_intr_reqp = (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

		ASSERT(curr_intr_reqp != NULL);

		tw->tw_num_tds = 1;

		if (ohci_tw_rebind_cookie(ohcip, pp, tw) != USB_SUCCESS) {
			ohci_deallocate_periodic_in_resource(ohcip, pp, tw);
			error = USB_FAILURE;
		} else if (ohci_allocate_tds_for_tw(ohcip, tw,
		    tw->tw_num_tds) != USB_SUCCESS) {
			ohci_deallocate_periodic_in_resource(ohcip, pp, tw);
			error = USB_FAILURE;
		}
	}

	if (error != USB_SUCCESS) {
		/*
		 * Set pipe state to stop polling and error to no
		 * resource. Don't insert any more interrupt polling
		 * requests.
		 */
		pp->pp_state = OHCI_PIPE_STATE_STOP_POLLING;
		pp->pp_error = USB_CR_NO_RESOURCES;
	} else {
		ohci_insert_intr_req(ohcip, pp, tw, 0);

		/* Increment number of interrupt request count */
		pp->pp_cur_periodic_req_cnt++;

		ASSERT(pp->pp_cur_periodic_req_cnt ==
		    pp->pp_max_periodic_req_cnt);
	}
}


/*
 * ohci_handle_one_xfer_completion:
 */
static void
ohci_handle_one_xfer_completion(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw)
{
	usba_pipe_handle_data_t	*ph = tw->tw_pipe_private->pp_pipe_handle;
	ohci_pipe_private_t	*pp = tw->tw_pipe_private;
	usb_intr_req_t		*curr_intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_one_xfer_completion: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));
	ASSERT(curr_intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER);

	pp->pp_state = OHCI_PIPE_STATE_IDLE;

	/*
	 * For one xfer, we need to copy back data ptr
	 * and free current request
	 */
	((usb_intr_req_t *)(pp->pp_client_periodic_in_reqp))->
	    intr_data = ((usb_intr_req_t *)
	    (tw->tw_curr_xfer_reqp))->intr_data;

	((usb_intr_req_t *)tw->tw_curr_xfer_reqp)->intr_data = NULL;

	/* Now free duplicate current request */
	usb_free_intr_req((usb_intr_req_t *)tw-> tw_curr_xfer_reqp);

	mutex_enter(&ph->p_mutex);
	ph->p_req_count--;
	mutex_exit(&ph->p_mutex);

	/* Make client's request the current request */
	tw->tw_curr_xfer_reqp = pp->pp_client_periodic_in_reqp;
	pp->pp_client_periodic_in_reqp = NULL;
}


/*
 * ohci_handle_isoc_td:
 *
 * Handle an isochronous Transfer Descriptor (TD).
 */
/* ARGSUSED */
static void
ohci_handle_isoc_td(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td,
	void			*tw_handle_callback_value)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	usb_isoc_req_t		*curr_isoc_reqp =
	    (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_handle_isoc_td: pp=0x%p tw=0x%p td=0x%p"
	    "isoc_reqp=0%p data=0x%p", (void *)pp, (void *)tw, (void *)td,
	    (void *)curr_isoc_reqp, (void *)curr_isoc_reqp->isoc_data);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Decrement the TDs counter and check whether all the isoc
	 * data has been send or received. If TDs counter reaches
	 * zero then inform client driver about completion current
	 * isoc request. Otherwise wait for completion of other isoc
	 * TDs or transactions on this pipe.
	 */
	if (--tw->tw_num_tds != 0) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_isoc_td: Number of TDs %d", tw->tw_num_tds);

		return;
	}

	/*
	 * If this is a isoc in pipe, return the data to the client.
	 * For a isoc out pipe, there is no need to do anything.
	 */
	if ((eptd->bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_OUT) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_handle_isoc_td: Isoc out pipe, isoc_reqp=0x%p,"
		    "data=0x%p", (void *)curr_isoc_reqp,
		    (void *)curr_isoc_reqp->isoc_data);

		ohci_do_byte_stats(ohcip, tw->tw_length,
		    eptd->bmAttributes, eptd->bEndpointAddress);

		/* Do the callback */
		ohci_hcdi_callback(ph, tw, USB_CR_OK);

		return;
	}

	/* Decrement number of IN isochronous request count */
	pp->pp_cur_periodic_req_cnt--;

	/* Call ohci_sendup_td_message to send message to upstream */
	ohci_sendup_td_message(ohcip, pp, tw, td, USB_CR_OK);

	/*
	 * If isochronous pipe state is still active, insert next isochronous
	 * request into the Host Controller's isochronous list.
	 */
	if (pp->pp_state != OHCI_PIPE_STATE_ACTIVE) {
		return;
	}

	if ((error = ohci_allocate_periodic_in_resource(ohcip, pp, tw, 0)) ==
	    USB_SUCCESS) {
		curr_isoc_reqp = (usb_isoc_req_t *)tw->tw_curr_xfer_reqp;

		ASSERT(curr_isoc_reqp != NULL);

		tw->tw_num_tds =
		    curr_isoc_reqp->isoc_pkts_count / OHCI_ISOC_PKTS_PER_TD;
		if (curr_isoc_reqp->isoc_pkts_count % OHCI_ISOC_PKTS_PER_TD) {
			tw->tw_num_tds++;
		}

		if (ohci_tw_rebind_cookie(ohcip, pp, tw) != USB_SUCCESS) {
			ohci_deallocate_periodic_in_resource(ohcip, pp, tw);
			error = USB_FAILURE;
		} else if (ohci_allocate_tds_for_tw(ohcip, tw,
		    tw->tw_num_tds) != USB_SUCCESS) {
			ohci_deallocate_periodic_in_resource(ohcip, pp, tw);
			error = USB_FAILURE;
		}
	}

	if (error != USB_SUCCESS ||
	    ohci_insert_isoc_req(ohcip, pp, tw, 0) != USB_SUCCESS) {
		/*
		 * Set pipe state to stop polling and error to no
		 * resource. Don't insert any more isoch polling
		 * requests.
		 */
		pp->pp_state = OHCI_PIPE_STATE_STOP_POLLING;
		pp->pp_error = USB_CR_NO_RESOURCES;

	} else {
		/* Increment number of IN isochronous request count */
		pp->pp_cur_periodic_req_cnt++;

		ASSERT(pp->pp_cur_periodic_req_cnt ==
		    pp->pp_max_periodic_req_cnt);
	}
}


/*
 * ohci_tw_rebind_cookie:
 *
 * If the cookie associated with a DMA buffer has been walked, the cookie
 * is not usable any longer. To reuse the DMA buffer, the DMA handle needs
 * to rebind for cookies.
 */
static int
ohci_tw_rebind_cookie(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;
	int			rval, i;
	uint_t			ccount;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_tw_rebind_cookie:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	if ((eptd->bmAttributes & USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH) {
		ASSERT(tw->tw_num_tds == tw->tw_ncookies);

		for (i = 0; i < tw->tw_num_tds; i++) {
			if (tw->tw_isoc_bufs[i].ncookies == 1) {

				/*
				 * no need to rebind when there is
				 * only one cookie in a buffer
				 */
				continue;
			}

			/* unbind the DMA handle before rebinding */
			rval = ddi_dma_unbind_handle(
			    tw->tw_isoc_bufs[i].dma_handle);
			ASSERT(rval == USB_SUCCESS);
			tw->tw_isoc_bufs[i].ncookies = 0;

			USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "rebind dma_handle %d", i);

			/* rebind the handle to get cookies */
			rval = ddi_dma_addr_bind_handle(
			    tw->tw_isoc_bufs[i].dma_handle, NULL,
			    (caddr_t)tw->tw_isoc_bufs[i].buf_addr,
			    tw->tw_isoc_bufs[i].length,
			    DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
			    DDI_DMA_DONTWAIT, NULL,
			    &tw->tw_isoc_bufs[i].cookie, &ccount);

			if ((rval == DDI_DMA_MAPPED) &&
			    (ccount <= OHCI_DMA_ATTR_TD_SGLLEN)) {
				tw->tw_isoc_bufs[i].ncookies = ccount;
			} else {

				return (USB_NO_RESOURCES);
			}
		}
	} else {
		if (tw->tw_cookie_idx != 0) {
			/* unbind the DMA handle before rebinding */
			rval = ddi_dma_unbind_handle(tw->tw_dmahandle);
			ASSERT(rval == DDI_SUCCESS);
			tw->tw_ncookies = 0;

			USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "rebind dma_handle");

			/* rebind the handle to get cookies */
			rval = ddi_dma_addr_bind_handle(
			    tw->tw_dmahandle, NULL,
			    (caddr_t)tw->tw_buf, tw->tw_length,
			    DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
			    DDI_DMA_DONTWAIT, NULL,
			    &tw->tw_cookie, &ccount);

			if (rval == DDI_DMA_MAPPED) {
				tw->tw_ncookies = ccount;
				tw->tw_dma_offs = 0;
				tw->tw_cookie_idx = 0;
			} else {

				return (USB_NO_RESOURCES);
			}
		}
	}

	return (USB_SUCCESS);
}


/*
 * ohci_sendup_td_message:
 *	copy data, if necessary and do callback
 */
static void
ohci_sendup_td_message(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td,
	usb_cr_t		error)
{
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	size_t			length = 0, skip_len = 0, residue;
	mblk_t			*mp;
	uchar_t			*buf;
	usb_opaque_t		curr_xfer_reqp = tw->tw_curr_xfer_reqp;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_sendup_td_message:");

	ASSERT(tw != NULL);

	length = tw->tw_length;

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		/*
		 * Get the correct length, adjust it for the setup size
		 * which is not part of the data length in control end
		 * points.  Update tw->tw_length for future references.
		 */
		if (((usb_ctrl_req_t *)curr_xfer_reqp)->ctrl_wLength) {
			tw->tw_length = length = length - OHCI_MAX_TD_BUF_SIZE;
		} else {
			tw->tw_length = length = length - SETUP_SIZE;
		}

		/* Set the length of the buffer to skip */
		skip_len = OHCI_MAX_TD_BUF_SIZE;

		if (Get_TD(td->hctd_ctrl_phase) != OHCI_CTRL_DATA_PHASE) {
			break;
		}
		/* FALLTHRU */
	case USB_EP_ATTR_BULK:
	case USB_EP_ATTR_INTR:
		/*
		 * If error is "data overrun", do not check for the
		 * "CurrentBufferPointer"  and return whatever data
		 * received to the client driver.
		 */
		if (error == USB_CR_DATA_OVERRUN) {
			break;
		}

		/*
		 * If "CurrentBufferPointer" of Transfer Descriptor
		 * (TD) is not equal to zero, then we received less
		 * data from the device than requested by us. In that
		 * case, get the actual received data size.
		 */
		if (Get_TD(td->hctd_cbp)) {
			residue = ohci_get_td_residue(ohcip, td);
			length = Get_TD(td->hctd_xfer_offs) +
			    Get_TD(td->hctd_xfer_len) - residue - skip_len;

			USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
			    "ohci_sendup_qtd_message: requested data %lu "
			    "received data %lu", tw->tw_length, length);
		}

		break;
	case USB_EP_ATTR_ISOCH:
	default:
		break;
	}

	/* Copy the data into the mblk_t */
	buf = (uchar_t *)tw->tw_buf + skip_len;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_sendup_qtd_message: length %lu error %d", length, error);

	/* Get the message block */
	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		mp = ((usb_ctrl_req_t *)curr_xfer_reqp)->ctrl_data;
		break;
	case USB_EP_ATTR_BULK:
		mp = ((usb_bulk_req_t *)curr_xfer_reqp)->bulk_data;
		break;
	case USB_EP_ATTR_INTR:
		mp = ((usb_intr_req_t *)curr_xfer_reqp)->intr_data;
		break;
	case USB_EP_ATTR_ISOCH:
		mp = ((usb_isoc_req_t *)curr_xfer_reqp)->isoc_data;
		break;
	}

	ASSERT(mp != NULL);

	if (length) {
		int i;
		uchar_t *p = mp->b_rptr;

		/*
		 * Update kstat byte counts
		 * The control endpoints don't have direction bits so in
		 * order for control stats to be counted correctly an in
		 * bit must be faked on a control read.
		 */
		if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_CONTROL) {
			ohci_do_byte_stats(ohcip, length,
			    eptd->bmAttributes, USB_EP_DIR_IN);
		} else {
			ohci_do_byte_stats(ohcip, length,
			    eptd->bmAttributes, eptd->bEndpointAddress);
		}

		if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_ISOCH) {
			for (i = 0; i < tw->tw_ncookies; i++) {
				Sync_IO_Buffer(
				    tw->tw_isoc_bufs[i].dma_handle,
				    tw->tw_isoc_bufs[i].length);

				ddi_rep_get8(tw->tw_isoc_bufs[i].mem_handle,
				    p, (uint8_t *)tw->tw_isoc_bufs[i].buf_addr,
				    tw->tw_isoc_bufs[i].length,
				    DDI_DEV_AUTOINCR);
				p += tw->tw_isoc_bufs[i].length;
			}
			tw->tw_pkt_idx = 0;
		} else {
			/* Sync IO buffer */
			Sync_IO_Buffer(tw->tw_dmahandle, (skip_len + length));

			/* Copy the data into the message */
			ddi_rep_get8(tw->tw_accesshandle,
			    mp->b_rptr, buf, length, DDI_DEV_AUTOINCR);
		}

		/* Increment the write pointer */
		mp->b_wptr = mp->b_wptr + length;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_sendup_td_message: Zero length packet");
	}

	ohci_hcdi_callback(ph, tw, error);
}


/*
 * ohci_get_td_residue:
 *
 * Calculate the bytes not transfered by the TD
 */
size_t
ohci_get_td_residue(
	ohci_state_t	*ohcip,
	ohci_td_t	*td)
{
	uint32_t	buf_addr, end_addr;
	size_t		residue;

	buf_addr = Get_TD(td->hctd_cbp);
	end_addr = Get_TD(td->hctd_buf_end);

	if ((buf_addr & 0xfffff000) ==
	    (end_addr & 0xfffff000)) {
		residue = end_addr - buf_addr + 1;
	} else {
		residue = OHCI_MAX_TD_BUF_SIZE -
		    (buf_addr & 0x00000fff) +
		    (end_addr & 0x00000fff) + 1;
	}

	return (residue);
}


/*
 * Miscellaneous functions
 */

/*
 * ohci_obtain_state:
 * NOTE: This function is also called from POLLED MODE.
 */
ohci_state_t *
ohci_obtain_state(dev_info_t	*dip)
{
	int			instance = ddi_get_instance(dip);
	ohci_state_t		*state = ddi_get_soft_state(
	    ohci_statep, instance);

	ASSERT(state != NULL);

	return (state);
}


/*
 * ohci_state_is_operational:
 *
 * Check the Host controller state and return proper values.
 */
int
ohci_state_is_operational(ohci_state_t	*ohcip)
{
	int				val;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	switch (ohcip->ohci_hc_soft_state) {
	case OHCI_CTLR_INIT_STATE:
	case OHCI_CTLR_SUSPEND_STATE:
		val = USB_FAILURE;
		break;
	case OHCI_CTLR_OPERATIONAL_STATE:
		val = USB_SUCCESS;
		break;
	case OHCI_CTLR_ERROR_STATE:
		val = USB_HC_HARDWARE_ERROR;
		break;
	default:
		val = USB_FAILURE;
		break;
	}

	return (val);
}


/*
 * ohci_do_soft_reset
 *
 * Do soft reset of ohci host controller.
 */
int
ohci_do_soft_reset(ohci_state_t	*ohcip)
{
	usb_frame_number_t	before_frame_number, after_frame_number;
	timeout_id_t		xfer_timer_id, rh_timer_id;
	ohci_regs_t		*ohci_save_regs;
	ohci_td_t		*done_head;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Increment host controller error count */
	ohcip->ohci_hc_error++;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_do_soft_reset:"
	    "Reset ohci host controller 0x%x", ohcip->ohci_hc_error);

	/*
	 * Allocate space for saving current Host Controller
	 * registers. Don't do any recovery if allocation
	 * fails.
	 */
	ohci_save_regs = (ohci_regs_t *)
	    kmem_zalloc(sizeof (ohci_regs_t), KM_NOSLEEP);

	if (ohci_save_regs == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_INTR,  ohcip->ohci_log_hdl,
		    "ohci_do_soft_reset: kmem_zalloc failed");

		return (USB_FAILURE);
	}

	/* Save current ohci registers */
	ohci_save_regs->hcr_control = Get_OpReg(hcr_control);
	ohci_save_regs->hcr_cmd_status = Get_OpReg(hcr_cmd_status);
	ohci_save_regs->hcr_intr_enable = Get_OpReg(hcr_intr_enable);
	ohci_save_regs->hcr_periodic_strt = Get_OpReg(hcr_periodic_strt);
	ohci_save_regs->hcr_frame_interval = Get_OpReg(hcr_frame_interval);
	ohci_save_regs->hcr_HCCA = Get_OpReg(hcr_HCCA);
	ohci_save_regs->hcr_bulk_head = Get_OpReg(hcr_bulk_head);
	ohci_save_regs->hcr_ctrl_head = Get_OpReg(hcr_ctrl_head);

	USB_DPRINTF_L4(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_do_soft_reset: Save reg = 0x%p", (void *)ohci_save_regs);

	/* Disable all list processing and interrupts */
	Set_OpReg(hcr_control, (Get_OpReg(hcr_control) & ~(HCR_CONTROL_CLE |
	    HCR_CONTROL_BLE | HCR_CONTROL_PLE | HCR_CONTROL_IE)));

	Set_OpReg(hcr_intr_disable, HCR_INTR_SO |
	    HCR_INTR_WDH | HCR_INTR_RD | HCR_INTR_UE |
	    HCR_INTR_FNO | HCR_INTR_SOF | HCR_INTR_MIE);

	/* Wait for few milliseconds */
	drv_usecwait(OHCI_TIMEWAIT);

	/* Root hub interrupt pipe timeout id */
	rh_timer_id = ohcip->ohci_root_hub.rh_intr_pipe_timer_id;

	/* Stop the root hub interrupt timer */
	if (rh_timer_id) {
		ohcip->ohci_root_hub.rh_intr_pipe_timer_id = 0;
		ohcip->ohci_root_hub.rh_intr_pipe_state =
		    OHCI_PIPE_STATE_IDLE;

		mutex_exit(&ohcip->ohci_int_mutex);
		(void) untimeout(rh_timer_id);
		mutex_enter(&ohcip->ohci_int_mutex);
	}

	/* Transfer timeout id */
	xfer_timer_id = ohcip->ohci_timer_id;

	/* Stop the global transfer timer */
	if (xfer_timer_id) {
		ohcip->ohci_timer_id = 0;
		mutex_exit(&ohcip->ohci_int_mutex);
		(void) untimeout(xfer_timer_id);
		mutex_enter(&ohcip->ohci_int_mutex);
	}

	/* Process any pending HCCA DoneHead */
	done_head = (ohci_td_t *)(uintptr_t)
	    (Get_HCCA(ohcip->ohci_hccap->HccaDoneHead) & HCCA_DONE_HEAD_MASK);

	if (ohci_check_done_head(ohcip, done_head) == USB_SUCCESS) {
		/* Reset the done head to NULL */
		Set_HCCA(ohcip->ohci_hccap->HccaDoneHead, 0);

		ohci_traverse_done_list(ohcip, done_head);
	}

	/* Process any pending hcr_done_head value */
	done_head = (ohci_td_t *)(uintptr_t)
	    (Get_OpReg(hcr_done_head) & HCCA_DONE_HEAD_MASK);
	if (ohci_check_done_head(ohcip, done_head) == USB_SUCCESS) {

		ohci_traverse_done_list(ohcip, done_head);
	}

	/* Do soft reset of ohci host controller */
	Set_OpReg(hcr_cmd_status, HCR_STATUS_RESET);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_do_soft_reset: Reset in progress");

	/* Wait for reset to complete */
	drv_usecwait(OHCI_RESET_TIMEWAIT);

	/* Reset HCCA HcFrameNumber */
	Set_HCCA(ohcip->ohci_hccap->HccaFrameNo, 0x00000000);

	/*
	 * Restore previous saved HC register value
	 * into the current HC registers.
	 */
	Set_OpReg(hcr_periodic_strt, (uint32_t)
	    ohci_save_regs->hcr_periodic_strt);

	Set_OpReg(hcr_frame_interval, (uint32_t)
	    ohci_save_regs->hcr_frame_interval);

	Set_OpReg(hcr_done_head, 0x0);

	Set_OpReg(hcr_bulk_curr, 0x0);

	Set_OpReg(hcr_bulk_head, (uint32_t)
	    ohci_save_regs->hcr_bulk_head);

	Set_OpReg(hcr_ctrl_curr, 0x0);

	Set_OpReg(hcr_ctrl_head, (uint32_t)
	    ohci_save_regs->hcr_ctrl_head);

	Set_OpReg(hcr_periodic_curr, 0x0);

	Set_OpReg(hcr_HCCA, (uint32_t)
	    ohci_save_regs->hcr_HCCA);

	Set_OpReg(hcr_intr_status, 0x0);

	/*
	 * Set HcInterruptEnable to enable all interrupts except
	 * Root Hub Status change interrupt.
	 */
	Set_OpReg(hcr_intr_enable,
	    HCR_INTR_SO | HCR_INTR_WDH | HCR_INTR_RD | HCR_INTR_UE |
	    HCR_INTR_FNO | HCR_INTR_SOF | HCR_INTR_MIE);

	/* Start Control and Bulk list processing */
	Set_OpReg(hcr_cmd_status, (HCR_STATUS_CLF | HCR_STATUS_BLF));

	/*
	 * Start up Control, Bulk, Periodic and Isochronous lists
	 * processing.
	 */
	Set_OpReg(hcr_control, (uint32_t)
	    (ohci_save_regs->hcr_control & (~HCR_CONTROL_HCFS)));

	/*
	 * Deallocate the space that allocated for saving
	 * HC registers.
	 */
	kmem_free((void *) ohci_save_regs, sizeof (ohci_regs_t));

	/* Resume the host controller */
	Set_OpReg(hcr_control, ((Get_OpReg(hcr_control) &
	    (~HCR_CONTROL_HCFS)) | HCR_CONTROL_RESUME));

	/* Wait for resume to complete */
	drv_usecwait(OHCI_RESUME_TIMEWAIT);

	/* Set the Host Controller Functional State to Operational */
	Set_OpReg(hcr_control, ((Get_OpReg(hcr_control) &
	    (~HCR_CONTROL_HCFS)) | HCR_CONTROL_OPERAT));

	/* Wait 10ms for HC to start sending SOF */
	drv_usecwait(OHCI_TIMEWAIT);

	/*
	 * Get the current usb frame number before waiting for few
	 * milliseconds.
	 */
	before_frame_number = ohci_get_current_frame_number(ohcip);

	/* Wait for few milliseconds */
	drv_usecwait(OHCI_TIMEWAIT);

	/*
	 * Get the current usb frame number after waiting for few
	 * milliseconds.
	 */
	after_frame_number = ohci_get_current_frame_number(ohcip);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
	    "ohci_do_soft_reset: Before Frm No 0x%llx After Frm No 0x%llx",
	    (unsigned long long)before_frame_number,
	    (unsigned long long)after_frame_number);

	if (after_frame_number <= before_frame_number) {

		USB_DPRINTF_L2(PRINT_MASK_INTR, ohcip->ohci_log_hdl,
		    "ohci_do_soft_reset: Soft reset failed");

		return (USB_FAILURE);
	}

	/* Start the timer for the root hub interrupt pipe polling */
	if (rh_timer_id) {
		ohcip->ohci_root_hub.rh_intr_pipe_timer_id =
		    timeout(ohci_handle_root_hub_status_change,
		    (void *)ohcip, drv_usectohz(OHCI_RH_POLL_TIME));

		ohcip->ohci_root_hub.
		    rh_intr_pipe_state = OHCI_PIPE_STATE_ACTIVE;
	}

	/* Start the global timer */
	if (xfer_timer_id) {
		ohcip->ohci_timer_id = timeout(ohci_xfer_timeout_handler,
		    (void *)ohcip, drv_usectohz(1000000));
	}

	return (USB_SUCCESS);
}


/*
 * ohci_get_current_frame_number:
 *
 * Get the current software based usb frame number.
 */
usb_frame_number_t
ohci_get_current_frame_number(ohci_state_t *ohcip)
{
	usb_frame_number_t	usb_frame_number;
	usb_frame_number_t	ohci_fno, frame_number;
	ohci_save_intr_sts_t	*ohci_intr_sts =
	    &ohcip->ohci_save_intr_sts;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Sync HCCA area only if this function
	 * is invoked in non interrupt context.
	 */
	if (!(ohci_intr_sts->ohci_intr_flag &
	    OHCI_INTR_HANDLING)) {

		/* Sync HCCA area */
		Sync_HCCA(ohcip);
	}

	ohci_fno = ohcip->ohci_fno;
	frame_number = Get_HCCA(ohcip->ohci_hccap->HccaFrameNo);

	/*
	 * Calculate current software based usb frame number.
	 *
	 * This code accounts for the fact that frame number is
	 * updated by the Host Controller before the ohci driver
	 * gets an FrameNumberOverflow (FNO) interrupt that will
	 * adjust Frame higher part.
	 *
	 * Refer ohci specification 1.0a, section 5.4, page 86.
	 */
	usb_frame_number = ((frame_number & 0x7FFF) | ohci_fno) +
	    (((frame_number & 0xFFFF) ^ ohci_fno) & 0x8000);

	return (usb_frame_number);
}


/*
 * ohci_cpr_cleanup:
 *
 * Cleanup ohci state and other ohci specific informations across
 * Check Point Resume (CPR).
 */
static	void
ohci_cpr_cleanup(ohci_state_t *ohcip)
{
	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Reset software part of usb frame number */
	ohcip->ohci_fno = 0;

	/* Reset Schedule Overrrun Error Counter */
	ohcip->ohci_so_error = 0;

	/* Reset HCCA HcFrameNumber */
	Set_HCCA(ohcip->ohci_hccap->HccaFrameNo, 0x00000000);
}


/*
 * ohci_get_xfer_attrs:
 *
 * Get the attributes of a particular xfer.
 */
static usb_req_attrs_t
ohci_get_xfer_attrs(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;
	usb_req_attrs_t		attrs = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_get_xfer_attrs:");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

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
	case USB_EP_ATTR_ISOCH:
		attrs = ((usb_isoc_req_t *)
		    tw->tw_curr_xfer_reqp)->isoc_attributes;
		break;
	}

	return (attrs);
}


/*
 * ohci_allocate_periodic_in_resource
 *
 * Allocate interrupt/isochronous request structure for the
 * interrupt/isochronous IN transfer.
 */
static int
ohci_allocate_periodic_in_resource(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uchar_t			ep_attr = ph->p_ep.bmAttributes;
	usb_intr_req_t		*curr_intr_reqp;
	usb_isoc_req_t		*curr_isoc_reqp;
	usb_opaque_t		client_periodic_in_reqp;
	size_t			length = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_allocate_periodic_in_resource:"
	    "pp = 0x%p tw = 0x%p flags = 0x%x", (void *)pp, (void *)tw, flags);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));
	ASSERT(tw->tw_curr_xfer_reqp == NULL);

	/* Get the client periodic in request pointer */
	client_periodic_in_reqp = pp->pp_client_periodic_in_reqp;

	/*
	 * If it a periodic IN request and periodic request is NULL,
	 * allocate corresponding usb periodic IN request for the
	 * current periodic polling request and copy the information
	 * from the saved periodic request structure.
	 */
	if ((ep_attr & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) {

		if (client_periodic_in_reqp) {

			/* Get the interrupt transfer length */
			length = ((usb_intr_req_t *)
			    client_periodic_in_reqp)->intr_len;

			curr_intr_reqp = usba_hcdi_dup_intr_req(
			    ph->p_dip, (usb_intr_req_t *)
			    client_periodic_in_reqp, length, flags);
		} else {
			curr_intr_reqp = usb_alloc_intr_req(
			    ph->p_dip, length, flags);
		}

		if (curr_intr_reqp == NULL) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_allocate_periodic_in_resource: Interrupt "
			    "request structure allocation failed");

			return (USB_NO_RESOURCES);
		}

		if (client_periodic_in_reqp == NULL) {
			/* For polled mode */
			curr_intr_reqp->
			    intr_attributes = USB_ATTRS_SHORT_XFER_OK;
			curr_intr_reqp->
			    intr_len = ph->p_ep.wMaxPacketSize;
		} else {
			/* Check and save the timeout value */
			tw->tw_timeout = (curr_intr_reqp->intr_attributes &
			    USB_ATTRS_ONE_XFER) ?
			    curr_intr_reqp->intr_timeout: 0;
		}

		tw->tw_curr_xfer_reqp = (usb_opaque_t)curr_intr_reqp;
		tw->tw_length = curr_intr_reqp->intr_len;
	} else {
		ASSERT(client_periodic_in_reqp != NULL);

		curr_isoc_reqp = usba_hcdi_dup_isoc_req(ph->p_dip,
		    (usb_isoc_req_t *)client_periodic_in_reqp, flags);

		if (curr_isoc_reqp == NULL) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_allocate_periodic_in_resource: Isochronous"
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

	pp->pp_state = OHCI_PIPE_STATE_ACTIVE;

	return (USB_SUCCESS);
}


/*
 * ohci_wait_for_sof:
 *
 * Wait for couple of SOF interrupts
 */
static int
ohci_wait_for_sof(ohci_state_t	*ohcip)
{
	usb_frame_number_t	before_frame_number, after_frame_number;
	clock_t			sof_time_wait;
	int			rval, sof_wait_count;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_wait_for_sof");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	/* Get the number of clock ticks to wait */
	sof_time_wait = drv_usectohz(OHCI_MAX_SOF_TIMEWAIT * 1000000);

	sof_wait_count = 0;

	/*
	 * Get the current usb frame number before waiting for the
	 * SOF interrupt event.
	 */
	before_frame_number = ohci_get_current_frame_number(ohcip);

	while (sof_wait_count < MAX_SOF_WAIT_COUNT) {
		/* Enable the SOF interrupt */
		Set_OpReg(hcr_intr_enable, HCR_INTR_SOF);

		ASSERT(Get_OpReg(hcr_intr_enable) & HCR_INTR_SOF);

		/* Wait for the SOF or timeout event */
		rval = cv_reltimedwait(&ohcip->ohci_SOF_cv,
		    &ohcip->ohci_int_mutex, sof_time_wait, TR_CLOCK_TICK);

		/*
		 * Get the current usb frame number after woken up either
		 * from SOF interrupt or timer expired event.
		 */
		after_frame_number = ohci_get_current_frame_number(ohcip);

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_wait_for_sof: before 0x%llx, after 0x%llx",
		    (unsigned long long)before_frame_number,
		    (unsigned long long)after_frame_number);

		/*
		 * Return failure, if we are woken up becuase of timer expired
		 * event and if usb frame number has not been changed.
		 */
		if ((rval == -1) &&
		    (after_frame_number <= before_frame_number)) {

			if ((ohci_do_soft_reset(ohcip)) != USB_SUCCESS) {

				USB_DPRINTF_L0(PRINT_MASK_LISTS,
				    ohcip->ohci_log_hdl, "No SOF interrupts");

				/* Set host controller soft state to error */
				ohcip->ohci_hc_soft_state =
				    OHCI_CTLR_ERROR_STATE;

				return (USB_FAILURE);
			}

			/* Get new usb frame number */
			after_frame_number = before_frame_number =
			    ohci_get_current_frame_number(ohcip);
		}

		ASSERT(after_frame_number >= before_frame_number);

		before_frame_number = after_frame_number;
		sof_wait_count++;
	}

	return (USB_SUCCESS);
}


/*
 * ohci_pipe_cleanup
 *
 * Cleanup ohci pipe.
 */
static void
ohci_pipe_cleanup(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	usb_cr_t		completion_reason;
	uint_t			pipe_state = pp->pp_state;
	uint_t			bit = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_pipe_cleanup: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	switch (pipe_state) {
	case OHCI_PIPE_STATE_CLOSE:
		if (OHCI_NON_PERIODIC_ENDPOINT(eptd)) {

			bit = ((eptd->bmAttributes &
			    USB_EP_ATTR_MASK) == USB_EP_ATTR_CONTROL) ?
			    HCR_CONTROL_CLE: HCR_CONTROL_BLE;

			Set_OpReg(hcr_control,
			    (Get_OpReg(hcr_control) & ~(bit)));

			/* Wait for the next SOF */
			(void) ohci_wait_for_sof(ohcip);

			break;
		}
		/* FALLTHROUGH */
	case OHCI_PIPE_STATE_RESET:
	case OHCI_PIPE_STATE_STOP_POLLING:
		/*
		 * Set the sKip bit to stop all transactions on
		 * this pipe
		 */
		ohci_modify_sKip_bit(ohcip, pp, SET_sKip,
		    OHCI_FLAGS_SLEEP | OHCI_FLAGS_DMA_SYNC);

		break;
	default:
		return;
	}

	/*
	 * Wait for processing all completed transfers and
	 * to send results to upstream.
	 */
	ohci_wait_for_transfers_completion(ohcip, pp);

	/* Save the data toggle information */
	ohci_save_data_toggle(ohcip, ph);

	/*
	 * Traverse the list of TD's on this endpoint and
	 * these TD's have outstanding transfer requests.
	 * Since the list processing is stopped, these tds
	 * can be deallocated.
	 */
	ohci_traverse_tds(ohcip, ph);

	/*
	 * If all of the endpoint's TD's have been deallocated,
	 * then the DMA mappings can be torn down. If not there
	 * are some TD's on the  done list that have not been
	 * processed. Tag these TD's  so that they are thrown
	 * away when the done list is processed.
	 */
	ohci_done_list_tds(ohcip, ph);

	/* Do callbacks for all unfinished requests */
	ohci_handle_outstanding_requests(ohcip, pp);

	/* Free DMA resources */
	ohci_free_dma_resources(ohcip, ph);

	switch (pipe_state) {
	case OHCI_PIPE_STATE_CLOSE:
		completion_reason = USB_CR_PIPE_CLOSING;
		break;
	case OHCI_PIPE_STATE_RESET:
	case OHCI_PIPE_STATE_STOP_POLLING:
		/* Set completion reason */
		completion_reason = (pipe_state ==
		    OHCI_PIPE_STATE_RESET) ?
		    USB_CR_PIPE_RESET: USB_CR_STOPPED_POLLING;

		/* Restore the data toggle information */
		ohci_restore_data_toggle(ohcip, ph);

		/*
		 * Clear the sKip bit to restart all the
		 * transactions on this pipe.
		 */
		ohci_modify_sKip_bit(ohcip, pp,
		    CLEAR_sKip, OHCI_FLAGS_NOSLEEP);

		/* Set pipe state to idle */
		pp->pp_state = OHCI_PIPE_STATE_IDLE;

		break;
	}

	ASSERT((Get_ED(pp->pp_ept->hced_tailp) & HC_EPT_TD_TAIL) ==
	    (Get_ED(pp->pp_ept->hced_headp) & HC_EPT_TD_HEAD));

	ASSERT((pp->pp_tw_head == NULL) && (pp->pp_tw_tail == NULL));

	/*
	 * Do the callback for the original client
	 * periodic IN request.
	 */
	if ((OHCI_PERIODIC_ENDPOINT(eptd)) &&
	    ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) ==
	    USB_EP_DIR_IN)) {

		ohci_do_client_periodic_in_req_callback(
		    ohcip, pp, completion_reason);
	}
}


/*
 * ohci_wait_for_transfers_completion:
 *
 * Wait for processing all completed transfers and to send results
 * to upstream.
 */
static void
ohci_wait_for_transfers_completion(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	ohci_trans_wrapper_t	*head_tw = pp->pp_tw_head;
	ohci_trans_wrapper_t	*next_tw;
	ohci_td_t		*tailp, *headp, *nextp;
	ohci_td_t		*head_td, *next_td;
	ohci_ed_t		*ept = pp->pp_ept;
	int			rval;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_wait_for_transfers_completion: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	headp = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip,
	    Get_ED(ept->hced_headp) & (uint32_t)HC_EPT_TD_HEAD));

	tailp = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip,
	    Get_ED(ept->hced_tailp) & (uint32_t)HC_EPT_TD_TAIL));

	rval = ohci_state_is_operational(ohcip);

	if (rval != USB_SUCCESS) {

		return;
	}

	pp->pp_count_done_tds = 0;

	/* Process the transfer wrappers for this pipe */
	next_tw = head_tw;
	while (next_tw) {
		head_td = (ohci_td_t *)next_tw->tw_hctd_head;
		next_td = head_td;

		if (head_td) {
			/*
			 * Walk through each TD for this transfer
			 * wrapper. If a TD still exists, then it
			 * is currently on the done list.
			 */
			while (next_td) {

				nextp = headp;

				while (nextp != tailp) {

					/* TD is on the ED */
					if (nextp == next_td) {
						break;
					}

					nextp = (ohci_td_t *)
					    (ohci_td_iommu_to_cpu(ohcip,
					    (Get_TD(nextp->hctd_next_td) &
					    HC_EPT_TD_TAIL)));
				}

				if (nextp == tailp) {
					pp->pp_count_done_tds++;
				}

				next_td = ohci_td_iommu_to_cpu(ohcip,
				    Get_TD(next_td->hctd_tw_next_td));
			}
		}

		next_tw = next_tw->tw_next;
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_wait_for_transfers_completion: count_done_tds = 0x%x",
	    pp->pp_count_done_tds);

	if (!pp->pp_count_done_tds) {

		return;
	}

	(void) cv_reltimedwait(&pp->pp_xfer_cmpl_cv, &ohcip->ohci_int_mutex,
	    drv_usectohz(OHCI_XFER_CMPL_TIMEWAIT * 1000000), TR_CLOCK_TICK);

	if (pp->pp_count_done_tds) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_wait_for_transfers_completion: No transfers "
		    "completion confirmation received for 0x%x requests",
		    pp->pp_count_done_tds);
	}
}


/*
 * ohci_check_for_transfers_completion:
 *
 * Check whether anybody is waiting for transfers completion event. If so, send
 * this event and also stop initiating any new transfers on this pipe.
 */
static void
ohci_check_for_transfers_completion(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_check_for_transfers_completion: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	if ((pp->pp_state == OHCI_PIPE_STATE_STOP_POLLING) &&
	    (pp->pp_error == USB_CR_NO_RESOURCES) &&
	    (pp->pp_cur_periodic_req_cnt == 0)) {

		/* Reset pipe error to zero */
		pp->pp_error = 0;

		/* Do callback for original request */
		ohci_do_client_periodic_in_req_callback(
		    ohcip, pp, USB_CR_NO_RESOURCES);
	}

	if (pp->pp_count_done_tds) {

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "ohci_check_for_transfers_completion:"
		    "count_done_tds = 0x%x", pp->pp_count_done_tds);

		/* Decrement the done td count */
		pp->pp_count_done_tds--;

		if (!pp->pp_count_done_tds) {
			USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
			    "ohci_check_for_transfers_completion:"
			    "Sent transfers completion event pp = 0x%p",
			    (void *)pp);

			/* Send the transfer completion signal */
			cv_signal(&pp->pp_xfer_cmpl_cv);
		}
	}
}


/*
 * ohci_save_data_toggle:
 *
 * Save the data toggle information.
 */
static void
ohci_save_data_toggle(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	uint_t			data_toggle;
	usb_cr_t		error = pp->pp_error;
	ohci_ed_t		*ed = pp->pp_ept;
	ohci_td_t		*headp, *tailp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_save_data_toggle: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Reset the pipe error value */
	pp->pp_error = USB_CR_OK;

	/* Return immediately if it is a control or isoc pipe */
	if (((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_CONTROL) || ((eptd->bmAttributes &
	    USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH)) {

		return;
	}

	headp = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip,
	    Get_ED(ed->hced_headp) & (uint32_t)HC_EPT_TD_HEAD));

	tailp = (ohci_td_t *)(ohci_td_iommu_to_cpu(ohcip,
	    Get_ED(ed->hced_tailp) & (uint32_t)HC_EPT_TD_TAIL));

	/*
	 * Retrieve the data toggle information either from the endpoint
	 * (ED) or from the transfer descriptor (TD) depending on the
	 * situation.
	 */
	if ((Get_ED(ed->hced_headp) & HC_EPT_Halt) || (headp == tailp)) {

		/* Get the data toggle information from the endpoint */
		data_toggle = (Get_ED(ed->hced_headp) &
		    HC_EPT_Carry)? DATA1:DATA0;
	} else {
		/*
		 * Retrieve the data toggle information depending on the
		 * master data toggle information saved in  the transfer
		 * descriptor (TD) at the head of the endpoint (ED).
		 *
		 * Check for master data toggle information .
		 */
		if (Get_TD(headp->hctd_ctrl) & HC_TD_MS_DT) {
			/* Get the data toggle information from td */
			data_toggle = (Get_TD(headp->hctd_ctrl) &
			    HC_TD_DT_1) ? DATA1:DATA0;
		} else {
			/* Get the data toggle information from the endpoint */
			data_toggle = (Get_ED(ed->hced_headp) &
			    HC_EPT_Carry)? DATA1:DATA0;
		}
	}

	/*
	 * If error is STALL, then, set
	 * data toggle to zero.
	 */
	if (error == USB_CR_STALL) {
		data_toggle = DATA0;
	}

	/*
	 * Save the data toggle information
	 * in the usb device structure.
	 */
	mutex_enter(&ph->p_mutex);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    data_toggle);
	mutex_exit(&ph->p_mutex);
}


/*
 * ohci_restore_data_toggle:
 *
 * Restore the data toggle information.
 */
static void
ohci_restore_data_toggle(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph)
{
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	uint_t			data_toggle = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_restore_data_toggle: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Return immediately if it is a control or isoc pipe.
	 */
	if (((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_CONTROL) || ((eptd->bmAttributes &
	    USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH)) {

		return;
	}

	mutex_enter(&ph->p_mutex);

	data_toggle = usba_hcdi_get_data_toggle(ph->p_usba_device,
	    ph->p_ep.bEndpointAddress);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    0);

	mutex_exit(&ph->p_mutex);

	/*
	 * Restore the data toggle bit depending on the
	 * previous data toggle information.
	 */
	if (data_toggle) {
		Set_ED(pp->pp_ept->hced_headp,
		    Get_ED(pp->pp_ept->hced_headp) | HC_EPT_Carry);
	} else {
		Set_ED(pp->pp_ept->hced_headp,
		    Get_ED(pp->pp_ept->hced_headp) & (~HC_EPT_Carry));
	}
}


/*
 * ohci_handle_outstanding_requests
 * NOTE: This function is also called from POLLED MODE.
 *
 * Deallocate interrupt/isochronous request structure for the
 * interrupt/isochronous IN transfer. Do the callbacks for all
 * unfinished requests.
 */
void
ohci_handle_outstanding_requests(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t	*eptd = &ph->p_ep;
	ohci_trans_wrapper_t	*curr_tw;
	ohci_trans_wrapper_t	*next_tw;
	usb_opaque_t		curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_handle_outstanding_requests: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Deallocate all the pre-allocated interrupt requests
	 */
	next_tw = pp->pp_tw_head;

	while (next_tw) {
		curr_tw = next_tw;
		next_tw = curr_tw->tw_next;

		curr_xfer_reqp = curr_tw->tw_curr_xfer_reqp;

		/* Deallocate current interrupt request */
		if (curr_xfer_reqp) {

			if ((OHCI_PERIODIC_ENDPOINT(eptd)) &&
			    (curr_tw->tw_direction == HC_TD_IN)) {

				/* Decrement periodic in request count */
				pp->pp_cur_periodic_req_cnt--;

				ohci_deallocate_periodic_in_resource(
				    ohcip, pp, curr_tw);
			} else {
				ohci_hcdi_callback(ph,
				    curr_tw, USB_CR_FLUSHED);
			}
		}
	}
}


/*
 * ohci_deallocate_periodic_in_resource
 *
 * Deallocate interrupt/isochronous request structure for the
 * interrupt/isochronous IN transfer.
 */
static void
ohci_deallocate_periodic_in_resource(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uchar_t			ep_attr = ph->p_ep.bmAttributes;
	usb_opaque_t		curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_deallocate_periodic_in_resource: "
	    "pp = 0x%p tw = 0x%p", (void *)pp, (void *)tw);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	curr_xfer_reqp = tw->tw_curr_xfer_reqp;

	/* Check the current periodic in request pointer */
	if (curr_xfer_reqp) {
		/*
		 * Reset periodic in request usb isoch
		 * packet request pointers to null.
		 */
		tw->tw_curr_xfer_reqp = NULL;
		tw->tw_curr_isoc_pktp = NULL;

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);

		/*
		 * Free pre-allocated interrupt
		 * or isochronous requests.
		 */
		switch (ep_attr & USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_INTR:
			usb_free_intr_req(
			    (usb_intr_req_t *)curr_xfer_reqp);
			break;
		case USB_EP_ATTR_ISOCH:
			usb_free_isoc_req(
			    (usb_isoc_req_t *)curr_xfer_reqp);
			break;
		}
	}
}


/*
 * ohci_do_client_periodic_in_req_callback
 *
 * Do callback for the original client periodic IN request.
 */
static void
ohci_do_client_periodic_in_req_callback(
	ohci_state_t		*ohcip,
	ohci_pipe_private_t	*pp,
	usb_cr_t		completion_reason)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_do_client_periodic_in_req_callback: "
	    "pp = 0x%p cc = 0x%x", (void *)pp, completion_reason);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * Check for Interrupt/Isochronous IN, whether we need to do
	 * callback for the original client's periodic IN request.
	 */
	if (pp->pp_client_periodic_in_reqp) {
		ASSERT(pp->pp_cur_periodic_req_cnt == 0);
		ohci_hcdi_callback(ph, NULL, completion_reason);
	}
}


/*
 * ohci_hcdi_callback()
 *
 * Convenience wrapper around usba_hcdi_cb() other than root hub.
 */
static void
ohci_hcdi_callback(
	usba_pipe_handle_data_t	*ph,
	ohci_trans_wrapper_t	*tw,
	usb_cr_t		completion_reason)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	uchar_t			attributes = ph->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK;
	ohci_pipe_private_t	*pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	usb_opaque_t		curr_xfer_reqp;
	uint_t			pipe_state = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_hcdi_callback: ph = 0x%p, tw = 0x%p, cr = 0x%x",
	    (void *)ph, (void *)tw, completion_reason);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Set the pipe state as per completion reason */
	switch (completion_reason) {
	case USB_CR_OK:
		pipe_state = pp->pp_state;
		break;
	case USB_CR_NO_RESOURCES:
	case USB_CR_NOT_SUPPORTED:
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_RESET:
		pipe_state = OHCI_PIPE_STATE_IDLE;
		break;
	case USB_CR_PIPE_CLOSING:
		break;
	default:
		/*
		 * Set the pipe state to error
		 * except for the isoc pipe.
		 */
		if (attributes != USB_EP_ATTR_ISOCH) {
			pipe_state = OHCI_PIPE_STATE_ERROR;
			pp->pp_error = completion_reason;
		}
		break;

	}

	pp->pp_state = pipe_state;

	if (tw && tw->tw_curr_xfer_reqp) {
		curr_xfer_reqp = tw->tw_curr_xfer_reqp;
		tw->tw_curr_xfer_reqp = NULL;
		tw->tw_curr_isoc_pktp = NULL;
	} else {
		ASSERT(pp->pp_client_periodic_in_reqp != NULL);

		curr_xfer_reqp = pp->pp_client_periodic_in_reqp;
		pp->pp_client_periodic_in_reqp = NULL;
	}

	ASSERT(curr_xfer_reqp != NULL);

	mutex_exit(&ohcip->ohci_int_mutex);

	usba_hcdi_cb(ph, curr_xfer_reqp, completion_reason);

	mutex_enter(&ohcip->ohci_int_mutex);
}


/*
 * ohci kstat functions
 */

/*
 * ohci_create_stats:
 *
 * Allocate and initialize the ohci kstat structures
 */
static void
ohci_create_stats(ohci_state_t	*ohcip)
{
	char			kstatname[KSTAT_STRLEN];
	const char		*dname = ddi_driver_name(ohcip->ohci_dip);
	char			*usbtypes[USB_N_COUNT_KSTATS] =
	    {"ctrl", "isoch", "bulk", "intr"};
	uint_t			instance = ohcip->ohci_instance;
	ohci_intrs_stats_t	*isp;
	int			i;

	if (OHCI_INTRS_STATS(ohcip) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,intrs",
		    dname, instance);
		OHCI_INTRS_STATS(ohcip) = kstat_create("usba", instance,
		    kstatname, "usb_interrupts", KSTAT_TYPE_NAMED,
		    sizeof (ohci_intrs_stats_t) / sizeof (kstat_named_t),
		    KSTAT_FLAG_PERSISTENT);

		if (OHCI_INTRS_STATS(ohcip)) {
			isp = OHCI_INTRS_STATS_DATA(ohcip);
			kstat_named_init(&isp->ohci_hcr_intr_total,
			    "Interrupts Total", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_not_claimed,
			    "Not Claimed", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_so,
			    "Schedule Overruns", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_wdh,
			    "Writeback Done Head", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_sof,
			    "Start Of Frame", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_rd,
			    "Resume Detected", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_ue,
			    "Unrecoverable Error", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_fno,
			    "Frame No. Overflow", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_rhsc,
			    "Root Hub Status Change", KSTAT_DATA_UINT64);
			kstat_named_init(&isp->ohci_hcr_intr_oc,
			    "Change In Ownership", KSTAT_DATA_UINT64);

			OHCI_INTRS_STATS(ohcip)->ks_private = ohcip;
			OHCI_INTRS_STATS(ohcip)->ks_update = nulldev;
			kstat_install(OHCI_INTRS_STATS(ohcip));
		}
	}

	if (OHCI_TOTAL_STATS(ohcip) == NULL) {
		(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,total",
		    dname, instance);
		OHCI_TOTAL_STATS(ohcip) = kstat_create("usba", instance,
		    kstatname, "usb_byte_count", KSTAT_TYPE_IO, 1,
		    KSTAT_FLAG_PERSISTENT);

		if (OHCI_TOTAL_STATS(ohcip)) {
			kstat_install(OHCI_TOTAL_STATS(ohcip));
		}
	}

	for (i = 0; i < USB_N_COUNT_KSTATS; i++) {
		if (ohcip->ohci_count_stats[i] == NULL) {
			(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,%s",
			    dname, instance, usbtypes[i]);
			ohcip->ohci_count_stats[i] = kstat_create("usba",
			    instance, kstatname, "usb_byte_count",
			    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);

			if (ohcip->ohci_count_stats[i]) {
				kstat_install(ohcip->ohci_count_stats[i]);
			}
		}
	}
}


/*
 * ohci_destroy_stats:
 *
 * Clean up ohci kstat structures
 */
static void
ohci_destroy_stats(ohci_state_t	*ohcip)
{
	int	i;

	if (OHCI_INTRS_STATS(ohcip)) {
		kstat_delete(OHCI_INTRS_STATS(ohcip));
		OHCI_INTRS_STATS(ohcip) = NULL;
	}

	if (OHCI_TOTAL_STATS(ohcip)) {
		kstat_delete(OHCI_TOTAL_STATS(ohcip));
		OHCI_TOTAL_STATS(ohcip) = NULL;
	}

	for (i = 0; i < USB_N_COUNT_KSTATS; i++) {
		if (ohcip->ohci_count_stats[i]) {
			kstat_delete(ohcip->ohci_count_stats[i]);
			ohcip->ohci_count_stats[i] = NULL;
		}
	}
}


/*
 * ohci_do_intrs_stats:
 *
 * ohci status information
 */
static void
ohci_do_intrs_stats(
	ohci_state_t	*ohcip,
	int		val)
{
	if (OHCI_INTRS_STATS(ohcip)) {
		OHCI_INTRS_STATS_DATA(ohcip)->ohci_hcr_intr_total.value.ui64++;
		switch (val) {
			case HCR_INTR_SO:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_so.value.ui64++;
				break;
			case HCR_INTR_WDH:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_wdh.value.ui64++;
				break;
			case HCR_INTR_SOF:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_sof.value.ui64++;
				break;
			case HCR_INTR_RD:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_rd.value.ui64++;
				break;
			case HCR_INTR_UE:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_ue.value.ui64++;
				break;
			case HCR_INTR_FNO:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_fno.value.ui64++;
				break;
			case HCR_INTR_RHSC:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_rhsc.value.ui64++;
				break;
			case HCR_INTR_OC:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_oc.value.ui64++;
				break;
			default:
				OHCI_INTRS_STATS_DATA(ohcip)->
				    ohci_hcr_intr_not_claimed.value.ui64++;
				break;
		}
	}
}


/*
 * ohci_do_byte_stats:
 *
 * ohci data xfer information
 */
static void
ohci_do_byte_stats(ohci_state_t	*ohcip, size_t len, uint8_t attr, uint8_t addr)
{
	uint8_t		type = attr & USB_EP_ATTR_MASK;
	uint8_t		dir = addr & USB_EP_DIR_MASK;

	if (dir == USB_EP_DIR_IN) {
		OHCI_TOTAL_STATS_DATA(ohcip)->reads++;
		OHCI_TOTAL_STATS_DATA(ohcip)->nread += len;
		switch (type) {
			case USB_EP_ATTR_CONTROL:
				OHCI_CTRL_STATS(ohcip)->reads++;
				OHCI_CTRL_STATS(ohcip)->nread += len;
				break;
			case USB_EP_ATTR_BULK:
				OHCI_BULK_STATS(ohcip)->reads++;
				OHCI_BULK_STATS(ohcip)->nread += len;
				break;
			case USB_EP_ATTR_INTR:
				OHCI_INTR_STATS(ohcip)->reads++;
				OHCI_INTR_STATS(ohcip)->nread += len;
				break;
			case USB_EP_ATTR_ISOCH:
				OHCI_ISOC_STATS(ohcip)->reads++;
				OHCI_ISOC_STATS(ohcip)->nread += len;
				break;
		}
	} else if (dir == USB_EP_DIR_OUT) {
		OHCI_TOTAL_STATS_DATA(ohcip)->writes++;
		OHCI_TOTAL_STATS_DATA(ohcip)->nwritten += len;
		switch (type) {
			case USB_EP_ATTR_CONTROL:
				OHCI_CTRL_STATS(ohcip)->writes++;
				OHCI_CTRL_STATS(ohcip)->nwritten += len;
				break;
			case USB_EP_ATTR_BULK:
				OHCI_BULK_STATS(ohcip)->writes++;
				OHCI_BULK_STATS(ohcip)->nwritten += len;
				break;
			case USB_EP_ATTR_INTR:
				OHCI_INTR_STATS(ohcip)->writes++;
				OHCI_INTR_STATS(ohcip)->nwritten += len;
				break;
			case USB_EP_ATTR_ISOCH:
				OHCI_ISOC_STATS(ohcip)->writes++;
				OHCI_ISOC_STATS(ohcip)->nwritten += len;
				break;
		}
	}
}


/*
 * ohci_print_op_regs:
 *
 * Print Host Controller's (HC) Operational registers.
 */
static void
ohci_print_op_regs(ohci_state_t *ohcip)
{
	uint_t			i;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\n\tOHCI%d Operational Registers\n",
	    ddi_get_instance(ohcip->ohci_dip));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_revision: 0x%x \t\thcr_control: 0x%x",
	    Get_OpReg(hcr_revision), Get_OpReg(hcr_control));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_cmd_status: 0x%x \t\thcr_intr_enable: 0x%x",
	    Get_OpReg(hcr_cmd_status), Get_OpReg(hcr_intr_enable));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_intr_disable: 0x%x \thcr_HCCA: 0x%x",
	    Get_OpReg(hcr_intr_disable), Get_OpReg(hcr_HCCA));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_periodic_curr: 0x%x \t\thcr_ctrl_head: 0x%x",
	    Get_OpReg(hcr_periodic_curr), Get_OpReg(hcr_ctrl_head));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_ctrl_curr: 0x%x  \t\thcr_bulk_head: 0x%x",
	    Get_OpReg(hcr_ctrl_curr), Get_OpReg(hcr_bulk_head));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_bulk_curr: 0x%x \t\thcr_done_head: 0x%x",
	    Get_OpReg(hcr_bulk_curr), Get_OpReg(hcr_done_head));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_frame_interval: 0x%x "
	    "\thcr_frame_remaining: 0x%x", Get_OpReg(hcr_frame_interval),
	    Get_OpReg(hcr_frame_remaining));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_frame_number: 0x%x  \thcr_periodic_strt: 0x%x",
	    Get_OpReg(hcr_frame_number), Get_OpReg(hcr_periodic_strt));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_transfer_ls: 0x%x \t\thcr_rh_descriptorA: 0x%x",
	    Get_OpReg(hcr_transfer_ls), Get_OpReg(hcr_rh_descriptorA));
	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\thcr_rh_descriptorB: 0x%x \thcr_rh_status: 0x%x",
	    Get_OpReg(hcr_rh_descriptorB), Get_OpReg(hcr_rh_status));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
	    "\tRoot hub port status");

	for (i = 0; i < (Get_OpReg(hcr_rh_descriptorA) & HCR_RHA_NDP); i++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, ohcip->ohci_log_hdl,
		    "\thcr_rh_portstatus 0x%x: 0x%x ", i,
		    Get_OpReg(hcr_rh_portstatus[i]));
	}
}


/*
 * ohci_print_ed:
 */
static void
ohci_print_ed(
	ohci_state_t	*ohcip,
	ohci_ed_t	*ed)
{
	uint_t		ctrl = Get_ED(ed->hced_ctrl);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_print_ed: ed = 0x%p", (void *)ed);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\thced_ctrl: 0x%x %s", ctrl,
	    ((Get_ED(ed->hced_headp) & HC_EPT_Halt) ? "halted": ""));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\ttoggle carry: 0x%x", Get_ED(ed->hced_headp) & HC_EPT_Carry);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tctrl: 0x%x", Get_ED(ed->hced_ctrl));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\ttailp: 0x%x", Get_ED(ed->hced_tailp));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\theadp: 0x%x", Get_ED(ed->hced_headp));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tnext: 0x%x", Get_ED(ed->hced_next));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tprev: 0x%x", Get_ED(ed->hced_prev));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tnode: 0x%x", Get_ED(ed->hced_node));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\treclaim_next: 0x%x", Get_ED(ed->hced_reclaim_next));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\treclaim_frame: 0x%x", Get_ED(ed->hced_reclaim_frame));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tstate: 0x%x", Get_ED(ed->hced_state));
}


/*
 * ohci_print_td:
 */
static void
ohci_print_td(
	ohci_state_t	*ohcip,
	ohci_td_t	*td)
{
	uint_t		i;
	uint_t		ctrl = Get_TD(td->hctd_ctrl);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "ohci_print_td: td = 0x%p", (void *)td);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tPID: 0x%x ", ctrl & HC_TD_PID);
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tDelay Intr: 0x%x ", ctrl & HC_TD_DI);
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tData Toggle: 0x%x ", ctrl & HC_TD_DT);
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tError Count: 0x%x ", ctrl & HC_TD_EC);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tctrl: 0x%x ", Get_TD(td->hctd_ctrl));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tcbp: 0x%x ", Get_TD(td->hctd_cbp));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tnext_td: 0x%x ", Get_TD(td->hctd_next_td));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tbuf_end: 0x%x ", Get_TD(td->hctd_buf_end));

	for (i = 0; i < 4; i++) {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
		    "\toffset[%d]: 0x%x ", i, Get_TD(td->hctd_offsets[i]));
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\ttrans_wrapper: 0x%x ", Get_TD(td->hctd_trans_wrapper));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tstate: 0x%x ", Get_TD(td->hctd_state));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\ttw_next_td: 0x%x ", Get_TD(td->hctd_tw_next_td));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ohcip->ohci_log_hdl,
	    "\tctrl_phase: 0x%x ", Get_TD(td->hctd_ctrl_phase));
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 *
 * define as a wrapper for sparc, or warlock will complain.
 */
#ifdef	__sparc
int
ohci_quiesce(dev_info_t *dip)
{
	return (ddi_quiesce_not_supported(dip));
}
#else
int
ohci_quiesce(dev_info_t *dip)
{
	ohci_state_t	*ohcip = ohci_obtain_state(dip);

	if (ohcip == NULL)
		return (DDI_FAILURE);

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	if (ohcip->ohci_flags & OHCI_INTR) {

		/* Disable all HC ED list processing */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) & ~(HCR_CONTROL_CLE |
		    HCR_CONTROL_BLE | HCR_CONTROL_PLE | HCR_CONTROL_IE)));

		/* Disable all HC interrupts */
		Set_OpReg(hcr_intr_disable,
		    (HCR_INTR_SO | HCR_INTR_WDH | HCR_INTR_RD | HCR_INTR_UE));

		/* Disable Master and SOF interrupts */
		Set_OpReg(hcr_intr_disable, (HCR_INTR_MIE | HCR_INTR_SOF));

		/* Set the Host Controller Functional State to Reset */
		Set_OpReg(hcr_control, ((Get_OpReg(hcr_control) &
		    (~HCR_CONTROL_HCFS)) | HCR_CONTROL_RESET));

		/*
		 * Workaround for ULI1575 chipset. Following OHCI Operational
		 * Memory Registers are not cleared to their default value
		 * on reset. Explicitly set the registers to default value.
		 */
		if (ohcip->ohci_vendor_id == PCI_ULI1575_VENID &&
		    ohcip->ohci_device_id == PCI_ULI1575_DEVID) {
			Set_OpReg(hcr_control, HCR_CONTROL_DEFAULT);
			Set_OpReg(hcr_intr_enable, HCR_INT_ENABLE_DEFAULT);
			Set_OpReg(hcr_HCCA, HCR_HCCA_DEFAULT);
			Set_OpReg(hcr_ctrl_head, HCR_CONTROL_HEAD_ED_DEFAULT);
			Set_OpReg(hcr_bulk_head, HCR_BULK_HEAD_ED_DEFAULT);
			Set_OpReg(hcr_frame_interval,
			    HCR_FRAME_INTERVAL_DEFAULT);
			Set_OpReg(hcr_periodic_strt,
			    HCR_PERIODIC_START_DEFAULT);
		}

		ohcip->ohci_hc_soft_state = OHCI_CTLR_SUSPEND_STATE;
	}

	/* Unmap the OHCI registers */
	if (ohcip->ohci_regs_handle) {
		/* Reset the host controller */
		Set_OpReg(hcr_cmd_status, HCR_STATUS_RESET);
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
	return (DDI_SUCCESS);
}
#endif	/* __sparc */
