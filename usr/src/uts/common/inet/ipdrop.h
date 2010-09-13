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

#ifndef _INET_IPDROP_H
#define	_INET_IPDROP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
/*
 * Opaque data type which will contain state about an entity that is dropping
 * a packet (e.g. IPsec SPD, IPsec SADB, TCP, IP forwarding, etc.).
 */
typedef struct ipdropper_s {
	char *ipd_name;
} ipdropper_t;

void ip_drop_register(ipdropper_t *, char *);
void ip_drop_unregister(ipdropper_t *);
void ip_drop_packet(mblk_t *, boolean_t, ill_t *, struct kstat_named *,
    ipdropper_t *);
void ip_drop_input(char *, mblk_t *, ill_t *);
void ip_drop_output(char *, mblk_t *, ill_t *);

/*
 * ip_dropstats - When a protocol developer comes up with a new reason to
 * drop a packet, it should have a bean counter placed here in this structure,
 * and an initializer in ipdrop.c's ip_drop_init().
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
	kstat_named_t ipds_sadb_inidle_timeout;
	kstat_named_t ipds_sadb_inidle_overflow;
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
	kstat_named_t ipds_spd_expired_frags;

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
	kstat_named_t ipds_esp_nat_t_ipsec;
	kstat_named_t ipds_esp_nat_t_ka;
	kstat_named_t ipds_esp_iv_wrap;

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

#endif /* _KERNEL */
#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPDROP_H */
