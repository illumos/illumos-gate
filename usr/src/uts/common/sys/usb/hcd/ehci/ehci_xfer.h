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

#ifndef _SYS_USB_EHCI_XFER_H
#define	_SYS_USB_EHCI_XFER_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Enchanced Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This header file describes the data structures and function prototypes
 * required for the EHCI Driver to perform different USB transfers.
 */

/* EHCI Queue Head (QH) related functions */
extern ehci_qh_t *ehci_alloc_qh(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			flag);
extern void	ehci_insert_qh(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
extern void	ehci_remove_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				boolean_t		reclaim);
extern void	ehci_deallocate_qh(
				ehci_state_t		*ehcip,
				ehci_qh_t		*old_qh);
extern uint32_t	ehci_qh_cpu_to_iommu(
				ehci_state_t		*ehcip,
				ehci_qh_t		*addr);
extern ehci_qh_t *ehci_qh_iommu_to_cpu(
				ehci_state_t		*ehcip,
				uintptr_t		addr);

/* EHCI Queue Element Transfer Descriptor (QTD) related functions */
extern ehci_trans_wrapper_t *ehci_allocate_ctrl_resources(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				usb_ctrl_req_t		*ctrl_reqp,
				usb_flags_t		usb_flags);
extern void	ehci_insert_ctrl_req(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		usb_flags);
extern ehci_trans_wrapper_t *ehci_allocate_bulk_resources(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				usb_bulk_req_t		*bulk_reqp,
				usb_flags_t		usb_flags);
extern void	ehci_insert_bulk_req(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_bulk_req_t		*bulk_reqp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
extern int	ehci_start_periodic_pipe_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_opaque_t		periodic_in_reqp,
				usb_flags_t		flags);
extern ehci_trans_wrapper_t *ehci_allocate_intr_resources(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_reqp,
				usb_flags_t		usb_flags);
extern void	ehci_insert_intr_req(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
extern int	ehci_stop_periodic_pipe_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
extern int	ehci_insert_qtd(
				ehci_state_t		*ehcip,
				uint32_t		qtd_ctrl,
				size_t			qtd_dma_offs,
				size_t			qtd_length,
				uint32_t		qtd_flag,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
extern void	ehci_remove_qtd_from_active_qtd_list(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*curr_qtd);
extern void	ehci_deallocate_qtd(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*old_qtd);
extern uint32_t	ehci_qtd_cpu_to_iommu(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*addr);
extern ehci_qtd_t *ehci_qtd_iommu_to_cpu(
				ehci_state_t		*ehcip,
				uintptr_t		addr);

/* Transfer Wrapper (TW) functions */
extern int	ehci_allocate_tds_for_tw(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				size_t			qtd_count);
extern void	ehci_stop_xfer_timer(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw,
				uint_t			flag);
extern void	ehci_deallocate_tw(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
extern void	ehci_free_dma_resources(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);

/* Miscillaneous functions */
extern int	ehci_allocate_intr_in_resource(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
extern void	ehci_deallocate_intr_in_resource(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
extern void	ehci_pipe_cleanup(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
extern void	ehci_check_for_transfers_completion(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
extern void	ehci_restore_data_toggle(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
extern void	ehci_handle_outstanding_requests(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
extern void	ehci_do_client_periodic_in_req_callback(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				usb_cr_t		completion_reason);
extern void	ehci_hcdi_callback(
				usba_pipe_handle_data_t	*ph,
				ehci_trans_wrapper_t	*tw,
				usb_cr_t		completion_reason);
extern void	ehci_handle_clear_tt_buffer(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);
extern void	ehci_handle_clear_tt_buffer_error(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*hub_pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*,
				usb_cr_t		error);
#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCI_XFER_H */
