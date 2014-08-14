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

#ifndef	_INET_IPSECESP_H
#define	_INET_IPSECESP_H

#include <inet/ip.h>
#include <inet/ipdrop.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/* Named Dispatch Parameter Management Structure */
typedef struct ipsecespparam_s {
	uint_t	ipsecesp_param_min;
	uint_t	ipsecesp_param_max;
	uint_t	ipsecesp_param_value;
	char	*ipsecesp_param_name;
} ipsecespparam_t;

/*
 * IPSECESP stack instances
 */
struct ipsecesp_stack {
	netstack_t		*ipsecesp_netstack;	/* Common netstack */

	caddr_t			ipsecesp_g_nd;
	struct ipsecespparam_s	*ipsecesp_params;
	kmutex_t		ipsecesp_param_lock;	/* Protects params */

	/* Packet dropper for ESP drops. */
	ipdropper_t		esp_dropper;

	kstat_t			*esp_ksp;
	struct esp_kstats_s	*esp_kstats;

	/*
	 * Keysock instance of ESP.  There can be only one per stack instance.
	 * Use atomic_cas_ptr() on this because I don't set it until
	 * KEYSOCK_HELLO comes down.
	 * Paired up with the esp_pfkey_q is the esp_event, which will age SAs.
	 */
	queue_t			*esp_pfkey_q;
	timeout_id_t		esp_event;

	sadbp_t			esp_sadb;
};
typedef struct ipsecesp_stack ipsecesp_stack_t;

/* Define *this* NDD variable here because we use it outside ESP proper. */
#define	ipsecesp_nat_keepalive_interval	\
	ipsecesp_params[14].ipsecesp_param_value

#endif	/* _KERNEL */

/*
 * For now, only provide "aligned" version of header.
 * If aligned version is needed, we'll go with the naming conventions then.
 */

typedef struct esph {
	uint32_t esph_spi;
	uint32_t esph_replay;
} esph_t;

/* No need for "old" ESP, just point a uint32_t *. */

#ifdef	__cplusplus
}
#endif

#endif /* _INET_IPSECESP_H */
