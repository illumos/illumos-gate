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

#ifndef	_INET_IPSECAH_H
#define	_INET_IPSECAH_H

#include <inet/ip.h>
#include <inet/ipdrop.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>

#ifdef _KERNEL
/* Named Dispatch Parameter Management Structure */
typedef struct ipsecahparam_s {
	uint_t	ipsecah_param_min;
	uint_t	ipsecah_param_max;
	uint_t	ipsecah_param_value;
	char	*ipsecah_param_name;
} ipsecahparam_t;

/*
 * Stats.  This may eventually become a full-blown SNMP MIB once that spec
 * stabilizes.
 */
typedef struct ah_kstats_s
{
	kstat_named_t ah_stat_num_aalgs;
	kstat_named_t ah_stat_good_auth;
	kstat_named_t ah_stat_bad_auth;
	kstat_named_t ah_stat_replay_failures;
	kstat_named_t ah_stat_replay_early_failures;
	kstat_named_t ah_stat_keysock_in;
	kstat_named_t ah_stat_out_requests;
	kstat_named_t ah_stat_acquire_requests;
	kstat_named_t ah_stat_bytes_expired;
	kstat_named_t ah_stat_out_discards;
	kstat_named_t ah_stat_crypto_sync;
	kstat_named_t ah_stat_crypto_async;
	kstat_named_t ah_stat_crypto_failures;
} ah_kstats_t;

/*
 * ahstack->ah_kstats is equal to ahstack->ah_ksp->ks_data if
 * kstat_create_netstack for ahstack->ah_ksp succeeds, but when it
 * fails, it will be NULL. Note this is done for all stack instances,
 * so it *could* fail. hence a non-NULL checking is done for
 * AH_BUMP_STAT and AH_DEBUMP_STAT
 */
#define	AH_BUMP_STAT(ahstack, x)					\
do {									\
	if (ahstack->ah_kstats != NULL)					\
		(ahstack->ah_kstats->ah_stat_ ## x).value.ui64++;	\
_NOTE(CONSTCOND)							\
} while (0)
#define	AH_DEBUMP_STAT(ahstack, x)					\
do {									\
	if (ahstack->ah_kstats != NULL)					\
		(ahstack->ah_kstats->ah_stat_ ## x).value.ui64--;	\
_NOTE(CONSTCOND)							\
} while (0)

/*
 * IPSECAH stack instances
 */
struct ipsecah_stack {
	netstack_t		*ipsecah_netstack;	/* Common netstack */

	caddr_t			ipsecah_g_nd;
	ipsecahparam_t		*ipsecah_params;
	kmutex_t		ipsecah_param_lock;	/* Protects params */

	sadbp_t			ah_sadb;

	/* Packet dropper for AH drops. */
	ipdropper_t		ah_dropper;

	kstat_t			*ah_ksp;
	ah_kstats_t		*ah_kstats;

	/*
	 * Keysock instance of AH.  There can be only one per stack instance.
	 * Use atomic_cas_ptr() on this because I don't set it until
	 * KEYSOCK_HELLO comes down.
	 * Paired up with the ah_pfkey_q is the ah_event, which will age SAs.
	 */
	queue_t			*ah_pfkey_q;
	timeout_id_t		ah_event;
};
typedef struct ipsecah_stack ipsecah_stack_t;

#endif	/* _KERNEL */

/*
 * For now, only provide "aligned" version of header.
 * If aligned version is needed, we'll go with the naming conventions then.
 */

typedef struct ah {
	uint8_t ah_nexthdr;
	uint8_t ah_length;
	uint16_t ah_reserved;
	uint32_t ah_spi;
	uint32_t ah_replay;
} ah_t;

#define	AH_BASELEN	12
#define	AH_TOTAL_LEN(ah)	(((ah)->ah_length << 2) + AH_BASELEN - \
					sizeof ((ah)->ah_replay))

/* "Old" AH, without replay.  For 1827-29 compatibility. */

typedef struct ahold {
	uint8_t ah_nexthdr;
	uint8_t ah_length;
	uint16_t ah_reserved;
	uint32_t ah_spi;
} ahold_t;

#define	AHOLD_BASELEN	8
#define	AHOLD_TOTAL_LEN(ah)	(((ah)->ah_length << 2) + AH_BASELEN)

#ifdef	__cplusplus
}
#endif

#endif /* _INET_IPSECAH_H */
