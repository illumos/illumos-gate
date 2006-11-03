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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INET_IPDROP_H
#define	_INET_IPDROP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Opaque data type which will contain state about an entity that is dropping
 * a packet (e.g. IPsec SPD, IPsec SADB, TCP, IP forwarding, etc.).
 */
typedef struct ipdropper_s {
	char *ipd_name;
} ipdropper_t;

void ip_drop_register(ipdropper_t *, char *);
void ip_drop_unregister(ipdropper_t *);
void ip_drop_packet(mblk_t *, boolean_t, ill_t *, ire_t *, struct kstat_named *,
    ipdropper_t *);

extern kstat_t *ip_drop_kstat;
extern struct ip_dropstats *ip_drop_types;
void ip_drop_init(void);
void ip_drop_destroy(void);

/*
 * ip_dropstats - When a protocol developer comes up with a new reason to
 * drop a packet, it should have a bean counter placed here in this structure,
 * an ipdrops_* definition for that bean counter, and an initializer in
 * ipdrop.c's ip_drop_init().
 *
 * This will suffice until we come up with a more dynamic way of adding
 * named kstats to a single kstat instance (if that is possible).
 */
struct ip_dropstats {
	/* TCP IPsec drop statistics. */
	kstat_named_t ipds_tcp_clear;
	kstat_named_t ipds_tcp_secure;
	kstat_named_t ipds_tcp_mismatch;
	kstat_named_t ipds_tcp_ipsec_alloc;

	/* SADB-specific drop statistics. */
	kstat_named_t ipds_sadb_inlarval_timeout;
	kstat_named_t ipds_sadb_inlarval_replace;
	kstat_named_t ipds_sadb_acquire_nomem;
	kstat_named_t ipds_sadb_acquire_toofull;
	kstat_named_t ipds_sadb_acquire_timeout;

	/* SPD drop statistics. */
	kstat_named_t ipds_spd_ahesp_diffid;
	kstat_named_t ipds_spd_loopback_mismatch;
	kstat_named_t ipds_spd_explicit;
	kstat_named_t ipds_spd_got_secure;
	kstat_named_t ipds_spd_got_clear;
	kstat_named_t ipds_spd_bad_ahalg;
	kstat_named_t ipds_spd_got_ah;
	kstat_named_t ipds_spd_bad_espealg;
	kstat_named_t ipds_spd_bad_espaalg;
	kstat_named_t ipds_spd_got_esp;
	kstat_named_t ipds_spd_got_selfencap;
	kstat_named_t ipds_spd_bad_selfencap;
	kstat_named_t ipds_spd_nomem;
	kstat_named_t ipds_spd_ah_badid;
	kstat_named_t ipds_spd_esp_badid;
	kstat_named_t ipds_spd_ah_innermismatch;
	kstat_named_t ipds_spd_esp_innermismatch;
	kstat_named_t ipds_spd_no_policy;
	kstat_named_t ipds_spd_malformed_packet;
	kstat_named_t ipds_spd_malformed_frag;
	kstat_named_t ipds_spd_overlap_frag;
	kstat_named_t ipds_spd_evil_frag;
	kstat_named_t ipds_spd_max_frags;

	/* ESP-specific drop statistics. */
	kstat_named_t ipds_esp_nomem;
	kstat_named_t ipds_esp_no_sa;
	kstat_named_t ipds_esp_early_replay;
	kstat_named_t ipds_esp_replay;
	kstat_named_t ipds_esp_bytes_expire;
	kstat_named_t ipds_esp_bad_padlen;
	kstat_named_t ipds_esp_bad_padding;
	kstat_named_t ipds_esp_bad_auth;
	kstat_named_t ipds_esp_crypto_failed;
	kstat_named_t ipds_esp_icmp;

	/* AH-specific drop statistics. */
	kstat_named_t ipds_ah_nomem;
	kstat_named_t ipds_ah_bad_v6_hdrs;
	kstat_named_t ipds_ah_bad_v4_opts;
	kstat_named_t ipds_ah_no_sa;
	kstat_named_t ipds_ah_bad_length;
	kstat_named_t ipds_ah_bad_auth;
	kstat_named_t ipds_ah_crypto_failed;
	kstat_named_t ipds_ah_early_replay;
	kstat_named_t ipds_ah_replay;
	kstat_named_t ipds_ah_bytes_expire;

	/* IP-specific drop statistics. */
	kstat_named_t ipds_ip_ipsec_not_loaded;
};

/*
 * Use this section to create easy-to-name definitions for specific IP Drop
 * statistics.  As a naming convention, prefix them with ipdrops_<foo>.
 */
/* TCP IPsec drop statistics. */
#define	ipdrops_tcp_clear	ip_drop_types->ipds_tcp_clear
#define	ipdrops_tcp_secure	ip_drop_types->ipds_tcp_secure
#define	ipdrops_tcp_mismatch	ip_drop_types->ipds_tcp_mismatch
#define	ipdrops_tcp_ipsec_alloc	ip_drop_types->ipds_tcp_ipsec_alloc

/* SADB-specific drop statistics. */
#define	ipdrops_sadb_inlarval_timeout ip_drop_types->ipds_sadb_inlarval_timeout
#define	ipdrops_sadb_inlarval_replace ip_drop_types->ipds_sadb_inlarval_replace
#define	ipdrops_sadb_acquire_nomem	ip_drop_types->ipds_sadb_acquire_nomem
#define	ipdrops_sadb_acquire_toofull	ip_drop_types->ipds_sadb_acquire_toofull
#define	ipdrops_sadb_acquire_timeout	ip_drop_types->ipds_sadb_acquire_timeout

/* SPD drop statistics. */
#define	ipdrops_spd_ahesp_diffid	ip_drop_types->ipds_spd_ahesp_diffid
#define	ipdrops_spd_loopback_mismatch ip_drop_types->ipds_spd_loopback_mismatch
#define	ipdrops_spd_explicit		ip_drop_types->ipds_spd_explicit
#define	ipdrops_spd_got_secure		ip_drop_types->ipds_spd_got_secure
#define	ipdrops_spd_got_clear		ip_drop_types->ipds_spd_got_clear
#define	ipdrops_spd_bad_ahalg		ip_drop_types->ipds_spd_bad_ahalg
#define	ipdrops_spd_got_ah		ip_drop_types->ipds_spd_got_ah
#define	ipdrops_spd_bad_espealg		ip_drop_types->ipds_spd_bad_espealg
#define	ipdrops_spd_bad_espaalg		ip_drop_types->ipds_spd_bad_espaalg
#define	ipdrops_spd_got_esp		ip_drop_types->ipds_spd_got_esp
#define	ipdrops_spd_got_selfencap	ip_drop_types->ipds_spd_got_selfencap
#define	ipdrops_spd_bad_selfencap	ip_drop_types->ipds_spd_bad_selfencap
#define	ipdrops_spd_nomem		ip_drop_types->ipds_spd_nomem
#define	ipdrops_spd_ah_badid		ip_drop_types->ipds_spd_ah_badid
#define	ipdrops_spd_esp_badid		ip_drop_types->ipds_spd_esp_badid
#define	ipdrops_spd_ah_innermismatch	\
				ip_drop_types->ipds_spd_ah_innermismatch
#define	ipdrops_spd_esp_innermismatch	\
				ip_drop_types->ipds_spd_esp_innermismatch
#define	ipdrops_spd_no_policy		ip_drop_types->ipds_spd_no_policy
#define	ipdrops_spd_malformed_packet	ip_drop_types->ipds_spd_malformed_packet
#define	ipdrops_spd_malformed_frag	ip_drop_types->ipds_spd_malformed_frag
#define	ipdrops_spd_overlap_frag	ip_drop_types->ipds_spd_overlap_frag
#define	ipdrops_spd_evil_frag		ip_drop_types->ipds_spd_evil_frag
#define	ipdrops_spd_max_frags		ip_drop_types->ipds_spd_max_frags

/* ESP-specific drop statistics. */
#define	ipdrops_esp_nomem		ip_drop_types->ipds_esp_nomem
#define	ipdrops_esp_no_sa		ip_drop_types->ipds_esp_no_sa
#define	ipdrops_esp_early_replay	ip_drop_types->ipds_esp_early_replay
#define	ipdrops_esp_replay		ip_drop_types->ipds_esp_replay
#define	ipdrops_esp_bytes_expire	ip_drop_types->ipds_esp_bytes_expire
#define	ipdrops_esp_bad_padlen		ip_drop_types->ipds_esp_bad_padlen
#define	ipdrops_esp_bad_padding		ip_drop_types->ipds_esp_bad_padding
#define	ipdrops_esp_bad_auth		ip_drop_types->ipds_esp_bad_auth
#define	ipdrops_esp_crypto_failed	ip_drop_types->ipds_esp_crypto_failed
#define	ipdrops_esp_icmp		ip_drop_types->ipds_esp_icmp

/* AH-specific drop statistics. */
#define	ipdrops_ah_nomem		ip_drop_types->ipds_ah_nomem
#define	ipdrops_ah_bad_v6_hdrs		ip_drop_types->ipds_ah_bad_v6_hdrs
#define	ipdrops_ah_bad_v4_opts		ip_drop_types->ipds_ah_bad_v4_opts
#define	ipdrops_ah_no_sa		ip_drop_types->ipds_ah_no_sa
#define	ipdrops_ah_bad_length		ip_drop_types->ipds_ah_bad_length
#define	ipdrops_ah_bad_auth		ip_drop_types->ipds_ah_bad_auth
#define	ipdrops_ah_crypto_failed	ip_drop_types->ipds_ah_crypto_failed
#define	ipdrops_ah_early_replay		ip_drop_types->ipds_ah_early_replay
#define	ipdrops_ah_replay		ip_drop_types->ipds_ah_replay
#define	ipdrops_ah_bytes_expire		ip_drop_types->ipds_ah_bytes_expire

/* IP-specific drop statistics. */
#define	ipdrops_ip_ipsec_not_loaded	ip_drop_types->ipds_ip_ipsec_not_loaded

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPDROP_H */
