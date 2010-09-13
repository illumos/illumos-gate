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

#ifndef _SYS_USB_UHCIHUB_H
#define	_SYS_USB_UHCIHUB_H


#ifdef __cplusplus
extern "C" {
#endif

int		uhci_init_root_hub(uhci_state_t *uhcip);
int		uhci_handle_root_hub_request(
			uhci_state_t		*uhcip,
			usba_pipe_handle_data_t  *pipe_handle,
			usb_ctrl_req_t		*req);
void		uhci_handle_root_hub_status_change(void *arg);
void		uhci_root_hub_intr_pipe_cleanup(uhci_state_t *,
							usb_cr_t);
int		uhci_root_hub_allocate_intr_pipe_resource(
			uhci_state_t		*uhcip,
			usb_flags_t		flags);

#define	UHCI_DISABLE_PORT	0
#define	UHCI_ENABLE_PORT	1
#define	UHCI_CLEAR_ENDIS_BIT	2

#define	UHCI_ENABLE_PORT_PWR	1
#define	UHCI_DISABLE_PORT_PWR	0

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_UHCIHUB_H */
