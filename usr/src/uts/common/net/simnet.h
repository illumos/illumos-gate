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

#ifndef	_SYS_SIMNET_H
#define	_SYS_SIMNET_H

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/dld_ioc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Simnet IOCTL commands handled via DLD driver */
#define	SIMNET_IOC_CREATE	SIMNETIOC(1)
#define	SIMNET_IOC_DELETE	SIMNETIOC(2)
#define	SIMNET_IOC_INFO		SIMNETIOC(3)
#define	SIMNET_IOC_MODIFY	SIMNETIOC(4)

typedef struct simnet_ioc_create {
	datalink_id_t	sic_link_id;
	uint_t		sic_type;	/* DL_ETHER or DL_WiFi */
	uint_t		sic_mac_len;
	uint_t		sic_flags;
	uchar_t		sic_mac_addr[MAXMACADDRLEN];
} simnet_ioc_create_t;

typedef struct simnet_ioc_delete {
	datalink_id_t	sid_link_id;
	uint_t		sid_flags;
} simnet_ioc_delete_t;

typedef struct simnet_ioc_info {
	datalink_id_t	sii_link_id;
	datalink_id_t	sii_peer_link_id;
	uint_t		sii_type;	/* DL_ETHER or DL_WiFi */
	uint_t		sii_mac_len;
	uint_t		sii_flags;
	uchar_t		sii_mac_addr[MAXMACADDRLEN];
} simnet_ioc_info_t;

typedef struct simnet_ioc_modify {
	datalink_id_t	sim_link_id;
	datalink_id_t	sim_peer_link_id;
	uint_t		sim_flags;
} simnet_ioc_modify_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SIMNET_H */
