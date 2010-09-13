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

#ifndef _SYS_USB_EHCI_INTR_H
#define	_SYS_USB_EHCI_INTR_H


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
 * related EHCI driver interrupt handling.
 */

/*
 * EHCI driver external interrupt function prototypes.
 */
extern void	ehci_handle_ue(ehci_state_t		*ehcip);
extern void	ehci_handle_frame_list_rollover(
				ehci_state_t		*ehcip);
extern void	ehci_handle_endpoint_reclaimation(
				ehci_state_t		*ehcip);
extern void	ehci_traverse_active_qtd_list(
				ehci_state_t		*ehcip);
extern usb_cr_t	ehci_check_for_error(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				uint_t			ctrl);
extern void	ehci_handle_error(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd,
				usb_cr_t		error);
extern void	ehci_handle_ctrl_qtd(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);
extern void	ehci_handle_bulk_qtd(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);
extern void	ehci_handle_intr_qtd(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCI_INTR_H */
