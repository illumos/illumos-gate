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

#ifndef _IP2MAC_H
#define	_IP2MAC_H
#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket_impl.h>
#include <net/if_dl.h>

#ifdef _KERNEL
/*
 * IP address -> link layer address conversion routines and structures.
 */
typedef struct ip2mac {
	struct sockaddr_storage	ip2mac_pa;
	struct sockaddr_dl	ip2mac_ha;
	uint_t			ip2mac_err;
	uint_t			ip2mac_ifindex;
} ip2mac_t;

#define	IP2MAC_RESOLVE	0x01	/* Asynchronously resolve, if needed */
#define	IP2MAC_LOOKUP	0x02	/* Lookup only */

typedef void *ip2mac_id_t;
typedef	void (ip2mac_callback_t)(ip2mac_t *, void *);

extern	ip2mac_id_t ip2mac(uint_t, ip2mac_t *, ip2mac_callback_t *,
    void *, zoneid_t);
extern	int ip2mac_cancel(ip2mac_id_t, zoneid_t);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _IP2MAC_H */
