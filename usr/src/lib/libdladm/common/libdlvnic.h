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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
	uint_t			va_vnic_id;
	char			va_dev_name[MAXNAMELEN + 1];
	vnic_mac_addr_type_t	va_mac_addr_type;
	uchar_t			va_mac_addr[ETHERADDRL];
	uint_t			va_mac_len;
} dladm_vnic_attr_sys_t;

/*
 * General operations flags.
 */
#define	DLADM_VNIC_OPT_TEMP	0x00000001
#define	DLADM_VNIC_OPT_AUTOID	0x00000002

/*
 * Modification flags for dladm_vnic_modify().
 */
#define	DLADM_VNIC_MODIFY_ADDR		0x01

extern dladm_status_t dladm_vnic_create(uint_t, char *, vnic_mac_addr_type_t,
    uchar_t *, int, uint_t *, uint32_t);
extern dladm_status_t dladm_vnic_modify(uint_t, uint32_t, vnic_mac_addr_type_t,
    uint_t, uchar_t *, uint32_t);
extern dladm_status_t dladm_vnic_delete(uint_t, uint32_t);
extern dladm_status_t dladm_vnic_walk_sys(
	dladm_status_t (*)(void *, dladm_vnic_attr_sys_t *), void *);
extern boolean_t dladm_vnic_mac_addr_str_to_type(const char *,
    vnic_mac_addr_type_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLVNIC_H */
