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
 *
 * Copyright 2024 H. William Welliver <william@welliver.org>
 */

#ifndef _LIBDLSIM_H
#define	_LIBDLSIM_H

#include <sys/mac.h>
#include <libdladm_impl.h>
#include <net/simnet.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_simnet_attr {
	datalink_id_t		sna_link_id;
	datalink_id_t		sna_peer_link_id;
	uchar_t			sna_mac_addr[MAXMACADDRLEN];
	uint_t			sna_mac_len;
	uint_t			sna_type;
} dladm_simnet_attr_t;

dladm_status_t dladm_simnet_create(dladm_handle_t, const char *,
    uint_t, const char *, uint32_t);
dladm_status_t dladm_simnet_delete(dladm_handle_t, datalink_id_t, uint32_t);
dladm_status_t dladm_simnet_modify(dladm_handle_t, datalink_id_t,
    datalink_id_t, uint32_t);
dladm_status_t dladm_simnet_info(dladm_handle_t, datalink_id_t,
    dladm_simnet_attr_t *, uint32_t);
dladm_status_t dladm_simnet_up(dladm_handle_t, datalink_id_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBDLSIM_H */
