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
 */

#ifndef _SYS_USB_EHCI_UTIL_H
#define	_SYS_USB_EHCI_UTIL_H


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
 * This header file describes the EHCI driver data structures and function
 * prototypes for the EHCI Host Controller initilization/deintilization,
 * Bandwidth Allocation and other miscellaneous functionalities.
 */

/*
 * EHCI driver initialization function prototypes.
 */
extern void	ehci_set_dma_attributes(ehci_state_t	*ehcip);
extern int	ehci_allocate_pools(ehci_state_t	*ehcip);
extern void	ehci_decode_ddi_dma_addr_bind_handle_result(
				ehci_state_t		*ehcip,
				int			result);
extern int	ehci_map_regs(ehci_state_t		*ehcip);
extern int	ehci_register_intrs_and_init_mutex(
				ehci_state_t		*ehcip);
extern int	ehci_init_ctlr(ehci_state_t		*ehcip,
				int			init_type);
extern usba_hcdi_ops_t	*ehci_alloc_hcdi_ops(
				ehci_state_t		*ehcip);

/*
 * EHCI driver deinitialization function prototypes.
 */
extern int	ehci_cleanup(ehci_state_t		*ehcip);
extern int	ehci_cpr_suspend(ehci_state_t		*ehcip);
extern int	ehci_cpr_resume(ehci_state_t		*ehcip);

/*
 * EHCI driver Bandwidth Allocation function prototypes.
 */
extern int	ehci_allocate_bandwidth(ehci_state_t	*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			*pnode,
				uchar_t			*smask,
				uchar_t			*cmask);
extern void	ehci_deallocate_bandwidth(ehci_state_t	*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			pnode,
				uchar_t			smask,
				uchar_t			cmask);
extern int	ehci_adjust_polling_interval(
				ehci_state_t		*ehcip,
				usb_ep_descr_t		*endpoint,
				usb_port_status_t	port_status);

/*
 * EHCI driver miscellaneous function prototypes.
 */
extern ehci_state_t	*ehci_obtain_state(
				dev_info_t		*dip);
extern int	ehci_state_is_operational(
				ehci_state_t		*ehcip);
extern int	ehci_do_soft_reset(
				ehci_state_t		*ehcip);
extern usb_req_attrs_t ehci_get_xfer_attrs(ehci_state_t	*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
extern usb_frame_number_t ehci_get_current_frame_number(
				ehci_state_t		*ehcip);
extern int	ehci_wait_for_sof(
				ehci_state_t		*ehcip);
extern void	ehci_toggle_scheduler(
				ehci_state_t		*ehcip);
extern void	ehci_toggle_scheduler_on_pipe(ehci_state_t *ehcip);

extern void	ehci_print_caps(ehci_state_t 		*ehcip);
extern void	ehci_print_regs(ehci_state_t 		*ehcip);
extern void	ehci_print_qh(ehci_state_t		*ehcip,
				ehci_qh_t		*qh);
extern void	ehci_print_qtd(ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd);
extern void	ehci_create_stats(ehci_state_t		*ehcip);
extern void	ehci_destroy_stats(ehci_state_t		*ehcip);
extern void	ehci_do_intrs_stats(ehci_state_t	*ehcip,
				int		val);
extern void	ehci_do_byte_stats(ehci_state_t		*ehcip,
				size_t		len,
				uint8_t		attr,
				uint8_t		addr);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCI_UTIL_H */
