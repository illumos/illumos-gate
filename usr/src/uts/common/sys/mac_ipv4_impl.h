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

#ifndef	_SYS_MAC_IPV4_IMPL_H
#define	_SYS_MAC_IPV4_IMPL_H

/*
 * IPv4 tunneling MAC Plugin
 */

#include <sys/mac.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * In addition to the mac_ipv4 plugin, the mac_6to4, and mac_ipv6 plugins
 * use the following functions.
 */
int mac_ipv4_unicst_verify(const void *, void *);
int mac_ipv4_multicst_verify(const void *, void *);
boolean_t mac_ipv4_sap_verify(uint32_t, uint32_t *, void *);
mblk_t *mac_ipv4_header(const void *, const void *, uint32_t, void *, mblk_t *,
    size_t);
int mac_ipv4_header_info(mblk_t *, void *, mac_header_info_t *);
boolean_t mac_ipv4_pdata_verify(void *, size_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_IPV4_IMPL_H */
