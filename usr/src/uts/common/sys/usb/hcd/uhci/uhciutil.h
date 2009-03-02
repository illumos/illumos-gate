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

#ifndef _SYS_USB_UHCIUTIL_H
#define	_SYS_USB_UHCIUTIL_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Universal Host Controller Driver(UHCI)
 *
 * The UHCI driver is a software driver which interfaces to the Universal
 * Serial Bus Driver(USBA) and the Host Controller(HC). The interface to
 * the Host Controller is defined by the UHCI.
 */
int	uhci_hcdi_pipe_open(usba_pipe_handle_data_t *pipe_handle,
		    usb_flags_t flags);
int	uhci_hcdi_pipe_close(usba_pipe_handle_data_t *pipe_handle,
		    usb_flags_t flags);
int	uhci_hcdi_pipe_reset(usba_pipe_handle_data_t *pipe_handle,
		    usb_flags_t usb_flags);
void	uhci_hcdi_pipe_reset_data_toggle(
	    usba_pipe_handle_data_t *pipe_handle);
int	uhci_hcdi_pipe_ctrl_xfer(usba_pipe_handle_data_t *,
		    usb_ctrl_req_t *, usb_flags_t);
int	uhci_hcdi_pipe_bulk_xfer(usba_pipe_handle_data_t *,
		    usb_bulk_req_t *, usb_flags_t);
int	uhci_hcdi_pipe_isoc_xfer(usba_pipe_handle_data_t *,
		    usb_isoc_req_t *, usb_flags_t);
int	uhci_hcdi_pipe_intr_xfer(usba_pipe_handle_data_t *,
		    usb_intr_req_t *, usb_flags_t);
int	uhci_hcdi_bulk_transfer_size(usba_device_t *usba_device,
		    size_t  *size);
int	uhci_hcdi_pipe_stop_intr_polling(
		    usba_pipe_handle_data_t *pipe_handle, usb_flags_t flags);
int	uhci_hcdi_pipe_stop_isoc_polling(usba_pipe_handle_data_t *ph,
		    usb_flags_t flags);
int	uhci_hcdi_get_current_frame_number(usba_device_t *usba_device,
		    usb_frame_number_t	*frame_number);
int	uhci_hcdi_get_max_isoc_pkts(usba_device_t *usba_device,
		    uint_t	*max_isoc_pkts_per_request);

/* Root hub prototypes */
int	uhci_handle_root_hub_request(
		    uhci_state_t		*uhcip,
		    usba_pipe_handle_data_t	*pipe_handle,
		    usb_ctrl_req_t	*req);

void	uhci_handle_ctrl_td(uhci_state_t *uhcip, uhci_td_t *td);
int	uhci_insert_bulk_td(uhci_state_t *uhcip,
		    usba_pipe_handle_data_t *ph,
		    usb_bulk_req_t *req, usb_flags_t flags);
void	uhci_handle_intr_td(uhci_state_t *uhcip, uhci_td_t *td);
void	uhci_sendup_td_message(uhci_state_t *uhcip, usb_cr_t,
		    uhci_trans_wrapper_t *tw);
usb_cr_t uhci_parse_td_error(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp, uhci_td_t *td);
void	uhci_process_submitted_td_queue(uhci_state_t *uhcip);
void	uhci_delete_td(uhci_state_t *uhcip, uhci_td_t *td);

/* global HCDI prototypes */
usba_hcdi_ops_t	*uhci_alloc_hcdi_ops(uhci_state_t *uhcip);
int	uhci_hcdi_polled_input_init(
		    usba_pipe_handle_data_t *uhcip,
		    uchar_t **polledbuf, usb_console_info_impl_t *info);
int	uhci_hcdi_polled_input_enter(usb_console_info_impl_t *info);
int	uhci_hcdi_polled_read(usb_console_info_impl_t *info, uint_t *num);
int	uhci_hcdi_polled_input_exit(usb_console_info_impl_t *info);
int	uhci_hcdi_polled_input_fini(usb_console_info_impl_t *info);
void	uhci_hcdi_callback(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp,
		    usba_pipe_handle_data_t *ph, uhci_trans_wrapper_t *tw,
		    usb_cr_t cr);

void	uhci_set_dma_attributes(uhci_state_t *uhcip);
void	uhci_remove_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp);
void	uhci_insert_qh(uhci_state_t *uhcip,
		    usba_pipe_handle_data_t *pipe_handle);
void	uhci_decode_ddi_dma_addr_bind_handle_result(uhci_state_t *uhcip,
		    int result);
int	uhci_allocate_pools(uhci_state_t *uhcip);
void	uhci_free_pools(uhci_state_t *uhcip);
int	uhci_init_ctlr(uhci_state_t *uhcip);
void	uhci_uninit_ctlr(uhci_state_t *uhcip);
int	uhci_map_regs(uhci_state_t *uhcip);
void	uhci_unmap_regs(uhci_state_t *uhcip);
int	uhci_insert_hc_td(uhci_state_t *uhcip,
		    uint32_t buffer_address, size_t hcgtd_length,
		    uhci_pipe_private_t	*pp, uhci_trans_wrapper_t *tw,
		    uchar_t PID, usb_req_attrs_t attrs);

int	uhci_allocate_periodic_in_resource(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp, uhci_trans_wrapper_t *tw,
		    usb_flags_t flags);
void	uhci_deallocate_periodic_in_resource(uhci_state_t *uhcip,
		    uhci_pipe_private_t *pp, uhci_trans_wrapper_t *tw);
void	uhci_do_intrs_stats(uhci_state_t *uhcip, int val);
void	uhci_do_byte_stats(uhci_state_t *, size_t, uint8_t, uint8_t);
void	uhci_deallocate_tw(uhci_state_t *uhcip, uhci_pipe_private_t *pp,
		    uhci_trans_wrapper_t *tw);

/* other generic global prototypes */
uhci_state_t	*uhci_obtain_state(dev_info_t *dip);
queue_head_t	*uhci_alloc_queue_head(uhci_state_t *uhcip);
int	uhci_state_is_operational(uhci_state_t *uhcip);
void	uhci_save_data_toggle(uhci_pipe_private_t *pp);
int	uhci_wait_for_sof(uhci_state_t *uhcip);
void	uhci_modify_td_active_bits(uhci_state_t *uhcip,
	    uhci_pipe_private_t *pp);
void	uhci_deallocate_bandwidth(uhci_state_t *uhcip,
		usba_pipe_handle_data_t *pipe_handle);
int	uhci_allocate_bandwidth(uhci_state_t *uhcip,
		    usba_pipe_handle_data_t *pipe_handle, uint_t *node);
void	uhci_remove_tds_tws(uhci_state_t *uhcip,
		usba_pipe_handle_data_t *ph);
void	uhci_free_tw(uhci_state_t *uhcip, uhci_trans_wrapper_t *tw);
void	uhci_insert_qh(uhci_state_t *uhcip,
		usba_pipe_handle_data_t *pipe_handle);
void	uhci_cmd_timeout_hdlr(void *arg);

/* Control prototypes */
int	uhci_insert_ctrl_td(uhci_state_t *uhcip,
		usba_pipe_handle_data_t *pipe_handle,
		usb_ctrl_req_t *req, usb_flags_t flags);

/* Intr prototypes */
int	uhci_insert_intr_td(uhci_state_t *uhcip,
		usba_pipe_handle_data_t *pipe_handle,
		usb_intr_req_t *req, usb_flags_t flags);

/* Bulk prototypes */
void	uhci_handle_bulk_td(uhci_state_t *uhcip, uhci_td_t *td);
void	uhci_fill_in_bulk_isoc_td(uhci_state_t *uhcip,
		uhci_td_t *current_td, uhci_td_t *next_td,
		uint32_t next_td_paddr, usba_pipe_handle_data_t *ph,
		uint_t offset, uint_t length,
		uhci_trans_wrapper_t *tw);
void	uhci_remove_bulk_tds_tws(uhci_state_t *uhcip,
		uhci_pipe_private_t *pp, int);

/* Isoc prototypes */
int	uhci_insert_isoc_td(uhci_state_t *uhcip,
		usba_pipe_handle_data_t *ph, usb_isoc_req_t *isoc_req,
		size_t length, usb_flags_t usb_flags);
void	uhci_handle_isoc_td(uhci_state_t *uhcip, uhci_td_t *td);
int	uhci_start_isoc_receive_polling(
		uhci_state_t *uhcip, usba_pipe_handle_data_t *ph,
		usb_isoc_req_t *isoc_req, usb_flags_t usb_flags);
void	uhci_remove_isoc_tds_tws(uhci_state_t *uhcip,
		uhci_pipe_private_t *ph);
uint64_t uhci_get_sw_frame_number(uhci_state_t *uhcip);
void	uhci_isoc_update_sw_frame_number(uhci_state_t *uhcip);

/* kstat support */
void	uhci_create_stats(uhci_state_t *uhcip);
void	uhci_destroy_stats(uhci_state_t *uhcip);

/* arithmetic goodies */
uint_t	pow_2(unsigned int x);
uint_t	log_2(unsigned int x);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_UHCIUTIL_H */
