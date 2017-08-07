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
 * Copyright (c) 2012 Nexenta Systems, Inc. All rights reserved.
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
 * Stats.  This may eventually become a full-blown SNMP MIB once that spec
 * stabilizes.
 */

typedef struct esp_kstats_s {
	kstat_named_t esp_stat_num_aalgs;
	kstat_named_t esp_stat_good_auth;
	kstat_named_t esp_stat_bad_auth;
	kstat_named_t esp_stat_bad_padding;
	kstat_named_t esp_stat_replay_failures;
	kstat_named_t esp_stat_replay_early_failures;
	kstat_named_t esp_stat_keysock_in;
	kstat_named_t esp_stat_out_requests;
	kstat_named_t esp_stat_acquire_requests;
	kstat_named_t esp_stat_bytes_expired;
	kstat_named_t esp_stat_out_discards;
	kstat_named_t esp_stat_crypto_sync;
	kstat_named_t esp_stat_crypto_async;
	kstat_named_t esp_stat_crypto_failures;
	kstat_named_t esp_stat_num_ealgs;
	kstat_named_t esp_stat_bad_decrypt;
	kstat_named_t esp_stat_sa_port_renumbers;
} esp_kstats_t;

/*
 * espstack->esp_kstats is equal to espstack->esp_ksp->ks_data if
 * kstat_create_netstack for espstack->esp_ksp succeeds, but when it
 * fails, it will be NULL. Note this is done for all stack instances,
 * so it *could* fail. hence a non-NULL checking is done for
 * ESP_BUMP_STAT and ESP_DEBUMP_STAT
 */
#define	ESP_BUMP_STAT(espstack, x)					\
do {									\
	if (espstack->esp_kstats != NULL)				\
		(espstack->esp_kstats->esp_stat_ ## x).value.ui64++;	\
_NOTE(CONSTCOND)							\
} while (0)

#define	ESP_DEBUMP_STAT(espstack, x)					\
do {									\
	if (espstack->esp_kstats != NULL)				\
		(espstack->esp_kstats->esp_stat_ ## x).value.ui64--;	\
_NOTE(CONSTCOND)							\
} while (0)

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

#define	ipsecesp_debug	ipsecesp_params[0].ipsecesp_param_value
#define	ipsecesp_age_interval ipsecesp_params[1].ipsecesp_param_value
#define	ipsecesp_age_int_max	ipsecesp_params[1].ipsecesp_param_max
#define	ipsecesp_reap_delay	ipsecesp_params[2].ipsecesp_param_value
#define	ipsecesp_replay_size	ipsecesp_params[3].ipsecesp_param_value
#define	ipsecesp_acquire_timeout	\
	ipsecesp_params[4].ipsecesp_param_value
#define	ipsecesp_larval_timeout	\
	ipsecesp_params[5].ipsecesp_param_value
#define	ipsecesp_default_soft_bytes	\
	ipsecesp_params[6].ipsecesp_param_value
#define	ipsecesp_default_hard_bytes	\
	ipsecesp_params[7].ipsecesp_param_value
#define	ipsecesp_default_soft_addtime	\
	ipsecesp_params[8].ipsecesp_param_value
#define	ipsecesp_default_hard_addtime	\
	ipsecesp_params[9].ipsecesp_param_value
#define	ipsecesp_default_soft_usetime	\
	ipsecesp_params[10].ipsecesp_param_value
#define	ipsecesp_default_hard_usetime	\
	ipsecesp_params[11].ipsecesp_param_value
#define	ipsecesp_log_unknown_spi	\
	ipsecesp_params[12].ipsecesp_param_value
#define	ipsecesp_padding_check	\
	ipsecesp_params[13].ipsecesp_param_value
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
