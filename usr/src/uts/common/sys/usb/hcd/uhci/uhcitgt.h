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

#ifndef	_SYS_USB_UHCITGT_H
#define	_SYS_USB_UHCITGT_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Shared function declarations
 */
queue_head_t	*uhci_alloc_queue_head(uhci_state_t *uhcip);
uhci_state_t	*uhci_obtain_state(dev_info_t *dip);

int		uhci_insert_ctrl_td(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*pipe_handle,
			usb_ctrl_req_t	*req,
			usb_flags_t		flags);
int		uhci_insert_bulk_td(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*pipe_handle,
			usb_bulk_req_t		*req,
			usb_flags_t		flags);
int		uhci_insert_intr_td(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*pipe_handle,
			usb_intr_req_t		*req,
			usb_flags_t		flags);
int		uhci_insert_isoc_td(
			uhci_state_t		*uhcip,
			usba_pipe_handle_data_t	*ph,
			usb_isoc_req_t		*isoc_req,
			size_t			length,
			usb_flags_t		usb_flags);

void		uhci_remove_qh(uhci_state_t *uhcip, uhci_pipe_private_t *pp);
void		uhci_insert_qh(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*pipe_handle);
void		uhci_modify_td_active_bits(
			uhci_state_t		*uhcip,
			uhci_pipe_private_t	*pp);

int		uhci_allocate_bandwidth(uhci_state_t *uhcip,
		    usba_pipe_handle_data_t *pipe_handle, uint_t *node);
void		uhci_deallocate_bandwidth(uhci_state_t *uhcip,
		    usba_pipe_handle_data_t *pipe_handle);
void		uhci_remove_tds_tws(uhci_state_t *uhcip,
		    usba_pipe_handle_data_t *ph);
void		uhci_remove_isoc_tds_tws(uhci_state_t *uhcip,
		    uhci_pipe_private_t *ph);
int		uhci_start_isoc_receive_polling(
			uhci_state_t		*uhcip,
			usba_pipe_handle_data_t	*ph,
			usb_isoc_req_t		*req,
			usb_flags_t		usb_flags);


void		uhci_save_data_toggle(uhci_pipe_private_t *pp);
int		uhci_handle_root_hub_request(
			uhci_state_t		*uhcip,
			usba_pipe_handle_data_t  *pipe_handle,
			usb_ctrl_req_t	*req);

void		uhci_remove_bulk_tds_tws(uhci_state_t *uhcip,
			uhci_pipe_private_t *pp,
			int what);
void		uhci_root_hub_reset_occurred(uhci_state_t *uhcip,
			usb_port_t port);
int		uhci_root_hub_allocate_intr_pipe_resource(
			uhci_state_t *uhcip,
			usb_flags_t flags);
void		uhci_root_hub_intr_pipe_cleanup(uhci_state_t *uhcip,
						usb_cr_t cr);
void		uhci_hcdi_callback(uhci_state_t *uhcip,
			uhci_pipe_private_t *pp,
			usba_pipe_handle_data_t *ph,
			uhci_trans_wrapper_t *tw,
			usb_cr_t cr);
int		uhci_allocate_periodic_in_resource(uhci_state_t *uhcip,
			uhci_pipe_private_t *pp,
			uhci_trans_wrapper_t *tw, usb_flags_t flags);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_UHCITGT_H */
