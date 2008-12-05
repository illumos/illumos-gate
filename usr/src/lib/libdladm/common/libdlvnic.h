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

#include <sys/types.h>
#include <netinet/in.h>
#include <libdladm.h>
#include <libdladm_impl.h>
#include <sys/mac_flow.h>
#include <sys/vnic.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_vnic_attr {
	datalink_id_t		va_vnic_id;
	datalink_id_t		va_link_id;
	vnic_mac_addr_type_t	va_mac_addr_type;
	uint_t			va_mac_len;
	uchar_t			va_mac_addr[MAXMACADDRLEN];
	int			va_mac_slot;
	uint_t			va_mac_prefix_len;
	uint16_t		va_vid;
	boolean_t		va_force;
	boolean_t		va_hwrings;
	mac_resource_props_t	va_resource_props;
} dladm_vnic_attr_t;

extern dladm_status_t	dladm_vnic_create(const char *, datalink_id_t,
			    vnic_mac_addr_type_t, uchar_t *, int, int *,
			    uint_t, uint16_t, datalink_id_t *,
			    dladm_arg_list_t *, uint32_t);

extern dladm_status_t	dladm_vnic_delete(datalink_id_t, uint32_t);
extern dladm_status_t	dladm_vnic_info(datalink_id_t, dladm_vnic_attr_t *,
			    uint32_t);

extern dladm_status_t	dladm_vnic_up(datalink_id_t, uint32_t);
extern dladm_status_t	dladm_vnic_str2macaddrtype(const char *,
			    vnic_mac_addr_type_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLVNIC_H */
