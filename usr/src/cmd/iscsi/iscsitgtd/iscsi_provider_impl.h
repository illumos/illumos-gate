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

#ifndef	_ISCSI_PROVIDER_IMPL_H
#define	_ISCSI_PROVIDER_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket_impl.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct sockaddr_storage uiscsicn_t;

typedef struct uiscsiproto {
	struct sockaddr_storage *uip_target_addr; /* target address */
	struct sockaddr_storage *uip_initiator_addr; /* initiator address */
	char *uip_target;	/* target IQN */
	char *uip_initiator;	/* initiator IQN */
	uint64_t uip_lun;	/* target logical unit number */

	uint32_t uip_itt;	/* initiator task tag */
	uint32_t uip_ttt;	/* target transfer tag */

	uint32_t uip_cmdsn;	/* command sequence number */
	uint32_t uip_statsn;	/* status sequence number */
	uint32_t uip_datasn;	/* data sequence number */

	uint32_t uip_datalen;	/* length of data payload */
	uint32_t uip_flags;	/* probe-specific flags */
} uiscsiproto_t;

typedef struct uiscsicmd {
	uint64_t uic_len;	/* CDB length */
	uint8_t *uic_cdb;	/* CDB data */
} uiscsicmd_t;

#ifdef	__cplusplus
}
#endif

#include "iscsi_provider.h"

#endif	/* _ISCSI_PROVIDER_IMPL_H */
