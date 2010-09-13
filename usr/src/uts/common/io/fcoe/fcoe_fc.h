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
#ifndef	_FCOE_FC_H_
#define	_FCOE_FC_H_

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern void fcoe_release_frame(fcoe_frame_t *);
extern fcoe_frame_t *fcoe_allocate_frame(fcoe_port_t *, uint32_t, void *);
extern void fcoe_mac_notify_link_up(void *);
extern void fcoe_mac_notify_link_down(void *);
extern int fcoe_create_port(dev_info_t *, fcoe_mac_t *, int);
extern int fcoe_delete_port(dev_info_t *, fcoeio_t *,
    datalink_id_t, uint64_t *is_target);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _FCOE_FC_H_ */
