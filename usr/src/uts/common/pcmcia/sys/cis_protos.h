/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _CIS_PROTOS_H
#define	_CIS_PROTOS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains all of the function prototypes for functions
 *	used by the CIS interpreter.
 *
 * Prototypes for general functions
 */
uint32_t	cis_list_create(cistpl_callout_t *, cs_socket_t *);
uint32_t	cis_list_destroy(cs_socket_t *);
uint32_t	cis_list_lcreate(cistpl_callout_t *, cisptr_t *,
			cis_info_t *, cisparse_t *, cs_socket_t *);
uint32_t	cis_list_ldestroy(cistpl_t **);
cistpl_t	*cis_get_ltuple(cistpl_t *, cisdata_t, uint32_t);
uint32_t	cistpl_devspeed(cistpl_t *, cisdata_t, uint32_t);
uint32_t	cistpl_expd_parse(cistpl_t *, uint32_t *);
uint32_t	cis_convert_devspeed(convert_speed_t *);
uint32_t	cis_convert_devsize(convert_size_t *);
uint32_t	cis_validate_longlink_acm(cisptr_t *);

/*
 * Prototypes for the tuple handlers
 */
uint32_t	cis_tuple_handler(cistpl_callout_t *, cistpl_t *, uint32_t,
					void *, cisdata_t);
uint32_t	cis_no_tuple_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cis_unknown_tuple_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_vers_1_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_config_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_device_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_cftable_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_jedec_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_vers_2_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_format_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_geometry_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_byteorder_handler(cistpl_callout_t *,
					cistpl_t *, uint32_t, void *);
uint32_t	cistpl_date_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_battery_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_org_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_funcid_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_funce_serial_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_funce_lan_handler(cistpl_callout_t *,
					cistpl_t *, uint32_t, void *);
uint32_t	cistpl_manfid_handler(cistpl_callout_t *, cistpl_t *,
					uint32_t, void *);
uint32_t	cistpl_linktarget_handler(cistpl_callout_t *,
					cistpl_t *, uint32_t, void *);
uint32_t	cistpl_longlink_ac_handler(cistpl_callout_t *,
					cistpl_t *, uint32_t, void *);
uint32_t	cistpl_longlink_mfc_handler(cistpl_callout_t *,
					cistpl_t *, uint32_t, void *);

char	*cis_getstr(cistpl_t *);

#ifdef	_KERNEL
caddr_t	cis_malloc(size_t);
void	cis_free(caddr_t);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _CIS_PROTOS_H */
