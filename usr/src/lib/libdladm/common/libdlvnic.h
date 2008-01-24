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

#ifndef _LIBDLVNIC_H
#define	_LIBDLVNIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>
#include <libdladm.h>
#include <sys/vnic.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_vnic_attr_sys {
	datalink_id_t		va_vnic_id;
	datalink_id_t		va_link_id;
	vnic_mac_addr_type_t	va_mac_addr_type;
	uchar_t			va_mac_addr[ETHERADDRL];
	uint_t			va_mac_len;
} dladm_vnic_attr_sys_t;

/*
 * Modification flags for dladm_vnic_modify().
 */
#define	DLADM_VNIC_MODIFY_ADDR		0x01

extern dladm_status_t dladm_vnic_create(const char *, datalink_id_t,
    vnic_mac_addr_type_t, uchar_t *, int, uint_t *, uint32_t);
extern dladm_status_t dladm_vnic_modify(datalink_id_t, uint32_t,
    vnic_mac_addr_type_t, uint_t, uchar_t *, uint32_t);
extern dladm_status_t dladm_vnic_delete(datalink_id_t, uint32_t);
extern dladm_status_t dladm_vnic_info(datalink_id_t, dladm_vnic_attr_sys_t *,
    uint32_t);
extern dladm_status_t dladm_vnic_str2macaddrtype(const char *,
    vnic_mac_addr_type_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLVNIC_H */
