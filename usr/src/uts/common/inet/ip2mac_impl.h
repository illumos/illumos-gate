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

#ifndef _IP2MAC_IMPL_H
#define	_IP2MAC_IMPL_H
/*
 * ip2mac implementation specific functions internal to IP
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <inet/ip_ndp.h>

#ifdef _KERNEL

extern void ncec_cb_dispatch(ncec_t *);
extern void ncec_ip2mac_response(ip2mac_t *, ncec_t *);
extern void ncec_cb_refhold_locked(ncec_t *);
extern void ncec_cb_refrele(ncec_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _IP2MAC_IMPL_H */
