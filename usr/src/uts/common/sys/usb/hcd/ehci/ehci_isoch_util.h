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

#ifndef _SYS_USB_EHCI_ISOCH_UTIL_H
#define	_SYS_USB_EHCI_ISOCH_UTIL_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Isochronous pool functions
 */
extern int ehci_allocate_isoc_pools(
	ehci_state_t		*ehcip);
extern int ehci_get_itd_pool_size();

/*
 * Isochronous Transfer Wrapper Functions
 */
extern ehci_isoc_xwrapper_t *ehci_allocate_itw_resources(
	ehci_state_t 		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			itw_length,
	usb_flags_t		usb_flags,
	size_t 			pkt_count);
extern void ehci_deallocate_itw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);

/*
 * Isochronous transfer descripter functions
 */
extern ehci_itd_t *ehci_allocate_itd(
	ehci_state_t		*ehcip);

extern void ehci_deallocate_itd(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*old_itd);
extern uint_t ehci_calc_num_itds(
	ehci_isoc_xwrapper_t	*itw,
	size_t 			pkt_count);
extern int ehci_allocate_itds_for_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	uint_t			itd_count);
extern void ehci_insert_itd_on_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);
extern void ehci_insert_itd_into_active_list(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);
extern void ehci_remove_itd_from_active_list(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);
extern ehci_itd_t *ehci_create_done_itd_list(
	ehci_state_t		*ehcip);
extern int ehci_insert_isoc_to_pfl(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);
extern void ehci_remove_isoc_from_pfl(
	ehci_state_t		*ehcip,
	ehci_itd_t		*curr_itd);

/*
 * Isochronous in resource functions
 */
extern int ehci_allocate_isoc_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*tw,
	usb_flags_t		flags);
extern void ehci_deallocate_isoc_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);

/*
 * Isochronous memory addr functions
 */
extern uint32_t ehci_itd_cpu_to_iommu(
	ehci_state_t		*ehcip,
	ehci_itd_t		*addr);

extern ehci_itd_t *ehci_itd_iommu_to_cpu(
	ehci_state_t		*ehcip,
	uintptr_t		addr);

/*
 * Error parsing functions
 */
extern void ehci_parse_isoc_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);

/*
 * print functions
 */
extern void ehci_print_itd(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);
extern void ehci_print_sitd(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCI_ISOCH_UTIL_H */
