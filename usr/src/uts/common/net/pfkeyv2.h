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
/*
 * Copyright 2017 Joyent, Inc.
 */

#ifndef	_NET_PFKEYV2_H
#define	_NET_PFKEYV2_H

/*
 * Definitions and structures for PF_KEY version 2.  See RFC 2367 for
 * more details.  SA == Security Association, which is what PF_KEY provides
 * an API for managing.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	PF_KEY_V2		2
#define	PFKEYV2_REVISION	200109L

/*
 * Base PF_KEY message.
 */

typedef struct sadb_msg {
	uint8_t sadb_msg_version;	/* Version, currently PF_KEY_V2 */
	uint8_t sadb_msg_type;		/* ADD, UPDATE, etc. */
	uint8_t sadb_msg_errno;		/* Error number from UNIX errno space */
	uint8_t sadb_msg_satype;	/* ESP, AH, etc. */
	uint16_t sadb_msg_len;		/* Length in 64-bit words. */
	uint16_t sadb_msg_reserved;	/* must be zero */
/*
 * Use the reserved field for extended diagnostic information on errno
 * responses.
 */
#define	sadb_x_msg_diagnostic sadb_msg_reserved
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint32_t sadb_x_msg_useq;	/* Set by originator */
			uint32_t sadb_x_msg_upid;	/* Set by originator */
		} sadb_x_msg_actual;
		uint64_t sadb_x_msg_alignment;
	} sadb_x_msg_u;
#define	sadb_msg_seq sadb_x_msg_u.sadb_x_msg_actual.sadb_x_msg_useq
#define	sadb_msg_pid sadb_x_msg_u.sadb_x_msg_actual.sadb_x_msg_upid
} sadb_msg_t;

/*
 * Generic extension header.
 */

typedef struct sadb_ext {
	union {
		/* Union is for guaranteeing 64-bit alignment. */
		struct {
			uint16_t sadb_x_ext_ulen;	/* In 64s, inclusive */
			uint16_t sadb_x_ext_utype;	/* 0 is reserved */
		} sadb_x_ext_actual;
		uint64_t sadb_x_ext_alignment;
	} sadb_x_ext_u;
#define	sadb_ext_len sadb_x_ext_u.sadb_x_ext_actual.sadb_x_ext_ulen
#define	sadb_ext_type sadb_x_ext_u.sadb_x_ext_actual.sadb_x_ext_utype
} sadb_ext_t;

/*
 * Security Association information extension.
 */

typedef struct sadb_sa {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t sadb_x_sa_ulen;
			uint16_t sadb_x_sa_uexttype;	/* ASSOCIATION */
			uint32_t sadb_x_sa_uspi;	/* Sec. Param. Index */
		} sadb_x_sa_uactual;
		uint64_t sadb_x_sa_alignment;
	} sadb_x_sa_u;
#define	sadb_sa_len sadb_x_sa_u.sadb_x_sa_uactual.sadb_x_sa_ulen
#define	sadb_sa_exttype sadb_x_sa_u.sadb_x_sa_uactual.sadb_x_sa_uexttype
#define	sadb_sa_spi sadb_x_sa_u.sadb_x_sa_uactual.sadb_x_sa_uspi
	uint8_t sadb_sa_replay;		/* Replay counter */
	uint8_t sadb_sa_state;		/* MATURE, DEAD, DYING, LARVAL */
	uint8_t sadb_sa_auth;		/* Authentication algorithm */
	uint8_t sadb_sa_encrypt;	/* Encryption algorithm */
	uint32_t sadb_sa_flags;		/* SA flags. */
} sadb_sa_t;

/*
 * SA Lifetime extension.  Already 64-bit aligned thanks to uint64_t fields.
 */

typedef struct sadb_lifetime {
	uint16_t sadb_lifetime_len;
	uint16_t sadb_lifetime_exttype;		/* SOFT, HARD, CURRENT */
	uint32_t sadb_lifetime_allocations;
	uint64_t sadb_lifetime_bytes;
	uint64_t sadb_lifetime_addtime;	/* These fields are assumed to hold */
	uint64_t sadb_lifetime_usetime;	/* >= sizeof (time_t). */
} sadb_lifetime_t;

/*
 * SA address information.
 */

typedef struct sadb_address {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t sadb_x_address_ulen;
			uint16_t sadb_x_address_uexttype; /* SRC, DST, PROXY */
			uint8_t sadb_x_address_uproto; /* Proto for ports... */
			uint8_t sadb_x_address_uprefixlen; /* Prefix length. */
			uint16_t sadb_x_address_ureserved; /* Padding */
		} sadb_x_address_actual;
		uint64_t sadb_x_address_alignment;
	} sadb_x_address_u;
#define	sadb_address_len \
	sadb_x_address_u.sadb_x_address_actual.sadb_x_address_ulen
#define	sadb_address_exttype \
	sadb_x_address_u.sadb_x_address_actual.sadb_x_address_uexttype
#define	sadb_address_proto \
	sadb_x_address_u.sadb_x_address_actual.sadb_x_address_uproto
#define	sadb_address_prefixlen \
	sadb_x_address_u.sadb_x_address_actual.sadb_x_address_uprefixlen
#define	sadb_address_reserved \
	sadb_x_address_u.sadb_x_address_actual.sadb_x_address_ureserved
	/* Followed by a sockaddr structure which may contain ports. */
} sadb_address_t;

/*
 * SA key information.
 */

typedef struct sadb_key {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t sadb_x_key_ulen;
			uint16_t sadb_x_key_uexttype;	/* AUTH, ENCRYPT */
			uint16_t sadb_x_key_ubits;	/* Actual len (bits) */
			uint16_t sadb_x_key_ureserved;
		} sadb_x_key_actual;
		uint64_t sadb_x_key_alignment;
	} sadb_x_key_u;
#define	sadb_key_len sadb_x_key_u.sadb_x_key_actual.sadb_x_key_ulen
#define	sadb_key_exttype sadb_x_key_u.sadb_x_key_actual.sadb_x_key_uexttype
#define	sadb_key_bits sadb_x_key_u.sadb_x_key_actual.sadb_x_key_ubits
#define	sadb_key_reserved sadb_x_key_u.sadb_x_key_actual.sadb_x_key_ureserved
	/* Followed by actual key(s) in canonical (outbound proc.) order. */
} sadb_key_t;

/*
 * SA Identity information.  Already 64-bit aligned thanks to uint64_t fields.
 */

typedef struct sadb_ident {
	uint16_t sadb_ident_len;
	uint16_t sadb_ident_exttype;	/* SRC, DST, PROXY */
	uint16_t sadb_ident_type;	/* FQDN, USER_FQDN, etc. */
	uint16_t sadb_ident_reserved;	/* Padding */
	uint64_t sadb_ident_id;		/* For userid, etc. */
	/* Followed by an identity null-terminate C string if present. */
} sadb_ident_t;

/*
 * SA sensitivity information.  This is mostly useful on MLS systems.
 */

typedef struct sadb_sens {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t sadb_x_sens_ulen;
			uint16_t sadb_x_sens_uexttype;	/* SENSITIVITY */
			uint32_t sadb_x_sens_udpd;	/* Protection domain */
		} sadb_x_sens_actual;
		uint64_t sadb_x_sens_alignment;
	} sadb_x_sens_u;
#define	sadb_sens_len sadb_x_sens_u.sadb_x_sens_actual.sadb_x_sens_ulen
#define	sadb_sens_exttype sadb_x_sens_u.sadb_x_sens_actual.sadb_x_sens_uexttype
#define	sadb_sens_dpd sadb_x_sens_u.sadb_x_sens_actual.sadb_x_sens_udpd
	uint8_t sadb_sens_sens_level;
	uint8_t sadb_sens_sens_len;		/* 64-bit words */
	uint8_t sadb_sens_integ_level;
	uint8_t sadb_sens_integ_len;		/* 64-bit words */
	uint32_t sadb_x_sens_flags;
	/*
	 * followed by two uint64_t arrays
	 * uint64_t sadb_sens_bitmap[sens_bitmap_len];
	 * uint64_t sadb_integ_bitmap[integ_bitmap_len];
	 */
} sadb_sens_t;

/*
 * We recycled the formerly reserved word for flags.
 */

#define	sadb_sens_reserved sadb_x_sens_flags

#define	SADB_X_SENS_IMPLICIT 0x1	 /* implicit labelling */
#define	SADB_X_SENS_UNLABELED 0x2	 /* peer is unlabeled */

/*
 * a proposal extension.  This is found in an ACQUIRE message, and it
 * proposes what sort of SA the kernel would like to ACQUIRE.
 */

/* First, a base structure... */

typedef struct sadb_x_propbase {
	uint16_t sadb_x_propb_len;
	uint16_t sadb_x_propb_exttype;	/* PROPOSAL, X_EPROP */
	union {
		struct {
			uint8_t sadb_x_propb_lenres_replay;
			uint8_t sadb_x_propb_lenres_eres;
			uint16_t sadb_x_propb_lenres_numecombs;
		} sadb_x_propb_lenres;
		struct {
			uint8_t sadb_x_propb_oldres_replay;
			uint8_t sadb_x_propb_oldres_reserved[3];
		} sadb_x_propb_oldres;
	} sadb_x_propb_u;
#define	sadb_x_propb_replay \
	sadb_x_propb_u.sadb_x_propb_lenres.sadb_x_propb_lenres_replay
#define	sadb_x_propb_reserved \
	sadb_x_propb_u.sadb_x_propb_oldres.sadb_x_propb_oldres_reserved
#define	sadb_x_propb_ereserved \
	sadb_x_propb_u.sadb_x_propb_lenres.sadb_x_propb_lenres_eres
#define	sadb_x_propb_numecombs \
	sadb_x_propb_u.sadb_x_propb_lenres.sadb_x_propb_lenres_numecombs
	/* Followed by sadb_comb[] array or sadb_ecomb[] array. */
} sadb_x_propbase_t;

/* Now, the actual sadb_prop structure, which will have alignment in it! */

typedef struct sadb_prop {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		sadb_x_propbase_t sadb_x_prop_actual;
		uint64_t sadb_x_prop_alignment;
	} sadb_x_prop_u;
#define	sadb_prop_len sadb_x_prop_u.sadb_x_prop_actual.sadb_x_propb_len
#define	sadb_prop_exttype sadb_x_prop_u.sadb_x_prop_actual.sadb_x_propb_exttype
#define	sadb_prop_replay sadb_x_prop_u.sadb_x_prop_actual.sadb_x_propb_replay
#define	sadb_prop_reserved \
	sadb_x_prop_u.sadb_x_prop_actual.sadb_x_propb_reserved
#define	sadb_x_prop_ereserved \
	sadb_x_prop_u.sadb_x_prop_actual.sadb_x_propb_ereserved
#define	sadb_x_prop_numecombs \
	sadb_x_prop_u.sadb_x_prop_actual.sadb_x_propb_numecombs
} sadb_prop_t;

/*
 * This is a proposed combination.  Many of these can follow a proposal
 * extension.  Already 64-bit aligned thanks to uint64_t fields.
 */

typedef struct sadb_comb {
	uint8_t sadb_comb_auth;			/* Authentication algorithm */
	uint8_t sadb_comb_encrypt;		/* Encryption algorithm */
	uint16_t sadb_comb_flags;		/* Comb. flags (e.g. PFS) */
	uint16_t sadb_comb_auth_minbits;	/* Bit strengths for auth */
	uint16_t sadb_comb_auth_maxbits;
	uint16_t sadb_comb_encrypt_minbits;	/* Bit strengths for encrypt */
	uint16_t sadb_comb_encrypt_maxbits;
	uint32_t sadb_comb_reserved;
	uint32_t sadb_comb_soft_allocations;	/* Lifetime proposals for */
	uint32_t sadb_comb_hard_allocations;	/* this combination. */
	uint64_t sadb_comb_soft_bytes;
	uint64_t sadb_comb_hard_bytes;
	uint64_t sadb_comb_soft_addtime;
	uint64_t sadb_comb_hard_addtime;
	uint64_t sadb_comb_soft_usetime;
	uint64_t sadb_comb_hard_usetime;
} sadb_comb_t;

/*
 * An extended combination that can comprise of many SA types.
 * A single combination has algorithms and SA types locked.
 * These are represented by algorithm descriptors, the second structure
 * in the list.  For example, if the EACQUIRE requests AH(MD5) + ESP(DES/null)
 * _or_ ESP(DES/MD5), it would have two combinations:
 *
 * COMB: algdes(AH, AUTH, MD5), algdes(ESP, CRYPT, DES)
 * COMB: algdes(ESP, AUTH, MD5), algdes(ESP, CRYPT, DES)
 *
 * If an SA type supports an algorithm type, and there's no descriptor,
 * assume it requires NONE, just like it were explicitly stated.
 * (This includes ESP NULL encryption, BTW.)
 *
 * Already 64-bit aligned thanks to uint64_t fields.
 */

typedef struct sadb_x_ecomb {
	uint8_t sadb_x_ecomb_numalgs;
	uint8_t sadb_x_ecomb_reserved;
	uint16_t sadb_x_ecomb_flags;	/* E.g. PFS? */
	uint32_t sadb_x_ecomb_reserved2;
	uint32_t sadb_x_ecomb_soft_allocations;
	uint32_t sadb_x_ecomb_hard_allocations;
	uint64_t sadb_x_ecomb_soft_bytes;
	uint64_t sadb_x_ecomb_hard_bytes;
	uint64_t sadb_x_ecomb_soft_addtime;
	uint64_t sadb_x_ecomb_hard_addtime;
	uint64_t sadb_x_ecomb_soft_usetime;
	uint64_t sadb_x_ecomb_hard_usetime;
} sadb_x_ecomb_t;

typedef struct sadb_x_algdesc {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint8_t sadb_x_algdesc_usatype;	/* ESP, AH, etc. */
			uint8_t sadb_x_algdesc_ualgtype; /* AUTH, CRYPT, COMP */
			uint8_t sadb_x_algdesc_ualg;	/* 3DES, MD5, etc. */
			uint8_t sadb_x_algdesc_ureserved;
			uint16_t sadb_x_algdesc_uminbits; /* Bit strengths. */
			uint16_t sadb_x_algdesc_umaxbits;
		} sadb_x_algdesc_actual;
		uint64_t sadb_x_algdesc_alignment;
	} sadb_x_algdesc_u;
#define	sadb_x_algdesc_satype \
	sadb_x_algdesc_u.sadb_x_algdesc_actual.sadb_x_algdesc_usatype
#define	sadb_x_algdesc_algtype \
	sadb_x_algdesc_u.sadb_x_algdesc_actual.sadb_x_algdesc_ualgtype
#define	sadb_x_algdesc_alg \
	sadb_x_algdesc_u.sadb_x_algdesc_actual.sadb_x_algdesc_ualg
#define	sadb_x_algdesc_reserved \
	sadb_x_algdesc_u.sadb_x_algdesc_actual.sadb_x_algdesc_ureserved
#define	sadb_x_algdesc_minbits \
	sadb_x_algdesc_u.sadb_x_algdesc_actual.sadb_x_algdesc_uminbits
#define	sadb_x_algdesc_maxbits \
	sadb_x_algdesc_u.sadb_x_algdesc_actual.sadb_x_algdesc_umaxbits
} sadb_x_algdesc_t;

/*
 * When key mgmt. registers with the kernel, the kernel will tell key mgmt.
 * its supported algorithms.
 */

typedef struct sadb_supported {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t sadb_x_supported_ulen;
			uint16_t sadb_x_supported_uexttype;
			uint32_t sadb_x_supported_ureserved;
		} sadb_x_supported_actual;
		uint64_t sadb_x_supported_alignment;
	} sadb_x_supported_u;
#define	sadb_supported_len \
	sadb_x_supported_u.sadb_x_supported_actual.sadb_x_supported_ulen
#define	sadb_supported_exttype \
	sadb_x_supported_u.sadb_x_supported_actual.sadb_x_supported_uexttype
#define	sadb_supported_reserved \
	sadb_x_supported_u.sadb_x_supported_actual.sadb_x_supported_ureserved
} sadb_supported_t;

/* First, a base structure... */
typedef struct sadb_x_algb {
	uint8_t sadb_x_algb_id;		/* Algorithm type. */
	uint8_t sadb_x_algb_ivlen;		/* IV len, in bits */
	uint16_t sadb_x_algb_minbits;	/* Min. key len (in bits) */
	uint16_t sadb_x_algb_maxbits;	/* Max. key length */
	union {
		uint16_t sadb_x_algb_ureserved;
		uint8_t sadb_x_algb_udefaults[2];
	} sadb_x_algb_union;

#define	sadb_x_algb_reserved sadb_x_algb_union.sadb_x_algb_ureserved
#define	sadb_x_algb_increment sadb_x_algb_union.sadb_x_algb_udefaults[0]
#define	sadb_x_algb_saltbits sadb_x_algb_union.sadb_x_algb_udefaults[1]
/*
 * alg_increment: the number of bits from a key length to the next
 */
} sadb_x_algb_t;

/* Now, the actual sadb_alg structure, which will have alignment in it. */
typedef struct sadb_alg {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		sadb_x_algb_t sadb_x_alg_actual;
		uint64_t sadb_x_alg_alignment;
	} sadb_x_alg_u;
#define	sadb_alg_id sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_id
#define	sadb_alg_ivlen sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_ivlen
#define	sadb_alg_minbits sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_minbits
#define	sadb_alg_maxbits sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_maxbits
#define	sadb_alg_reserved sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_reserved
#define	sadb_x_alg_increment \
	sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_increment
#define	sadb_x_alg_saltbits sadb_x_alg_u.sadb_x_alg_actual.sadb_x_algb_saltbits
} sadb_alg_t;

/*
 * If key mgmt. needs an SPI in a range (including 0 to 0xFFFFFFFF), it
 * asks the kernel with this extension in the SADB_GETSPI message.
 */

typedef struct sadb_spirange {
	uint16_t sadb_spirange_len;
	uint16_t sadb_spirange_exttype;	/* SPI_RANGE */
	uint32_t sadb_spirange_min;
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint32_t sadb_x_spirange_umax;
			uint32_t sadb_x_spirange_ureserved;
		} sadb_x_spirange_actual;
		uint64_t sadb_x_spirange_alignment;
	} sadb_x_spirange_u;
#define	sadb_spirange_max \
	sadb_x_spirange_u.sadb_x_spirange_actual.sadb_x_spirange_umax
#define	sadb_spirange_reserved \
	sadb_x_spirange_u.sadb_x_spirange_actual.sadb_x_spirange_ureserved
} sadb_spirange_t;

/*
 * For the "extended REGISTER" which'll tell the kernel to send me
 * "extended ACQUIREs".
 */

typedef struct sadb_x_ereg {
	/* Union is for guaranteeing 64-bit alignment. */
	union {
		struct {
			uint16_t sadb_x_ereg_ulen;
			uint16_t sadb_x_ereg_uexttype;	/* X_EREG */
			/* Array of SA types, 0-terminated. */
			uint8_t sadb_x_ereg_usatypes[4];
		} sadb_x_ereg_actual;
		uint64_t sadb_x_ereg_alignment;
	} sadb_x_ereg_u;
#define	sadb_x_ereg_len \
	sadb_x_ereg_u.sadb_x_ereg_actual.sadb_x_ereg_ulen
#define	sadb_x_ereg_exttype \
	sadb_x_ereg_u.sadb_x_ereg_actual.sadb_x_ereg_uexttype
#define	sadb_x_ereg_satypes \
	sadb_x_ereg_u.sadb_x_ereg_actual.sadb_x_ereg_usatypes
} sadb_x_ereg_t;

/*
 * For conveying a Key Management Cookie with SADB_GETSPI, SADB_ADD,
 * SADB_ACQUIRE, or SADB_X_INVERSE_ACQUIRE.
 */

typedef struct sadb_x_kmc {
	uint16_t sadb_x_kmc_len;
	uint16_t sadb_x_kmc_exttype;	/* X_KM_COOKIE */
	uint32_t sadb_x_kmc_proto;	/* KM protocol */
	union {
		struct {
			uint32_t sadb_x_kmc_ucookie;	/* KMP-specific */
			uint32_t sadb_x_kmc_ureserved;	/* Must be zero */
		} sadb_x_kmc_actual;
		uint64_t sadb_x_kmc_ucookie64;
	} sadb_x_kmc_u;
#define	sadb_x_kmc_cookie sadb_x_kmc_u.sadb_x_kmc_actual.sadb_x_kmc_ucookie
#define	sadb_x_kmc_reserved sadb_x_kmc_u.sadb_x_kmc_actual.sadb_x_kmc_ureserved
#define	sadb_x_kmc_cookie64 sadb_x_kmc_u.sadb_x_kmc_ucookie64
} sadb_x_kmc_t;

typedef struct sadb_x_pair {
	union {
		/* Union is for guaranteeing 64-bit alignment. */
		struct {
			uint16_t sadb_x_pair_ulen;
			uint16_t sadb_x_pair_uexttype;
			uint32_t sadb_x_pair_uspi;	/* SPI of paired SA */
		} sadb_x_pair_actual;
		uint64_t sadb_x_ext_alignment;
	} sadb_x_pair_u;
#define	sadb_x_pair_len sadb_x_pair_u.sadb_x_pair_actual.sadb_x_pair_ulen
#define	sadb_x_pair_exttype \
	sadb_x_pair_u.sadb_x_pair_actual.sadb_x_pair_uexttype
#define	sadb_x_pair_spi sadb_x_pair_u.sadb_x_pair_actual.sadb_x_pair_uspi
} sadb_x_pair_t;

/*
 * For the Sequence numbers to be used with SADB_DUMP, SADB_GET, SADB_UPDATE.
 */

typedef struct sadb_x_replay_ctr {
	uint16_t sadb_x_rc_len;
	uint16_t sadb_x_rc_exttype;
	uint32_t sadb_x_rc_replay32;    /* For 240x SAs. */
	uint64_t sadb_x_rc_replay64;    /* For 430x SAs. */
} sadb_x_replay_ctr_t;

/*
 * For extended DUMP request. Dumps the SAs which were idle for
 * longer than the timeout specified.
 */

typedef struct sadb_x_edump {
	uint16_t sadb_x_edump_len;
	uint16_t sadb_x_edump_exttype;
	uint32_t sadb_x_edump_reserved;
	uint64_t sadb_x_edump_timeout;
} sadb_x_edump_t;

/*
 * Base message types.
 */

#define	SADB_RESERVED	0
#define	SADB_GETSPI	1
#define	SADB_UPDATE	2
#define	SADB_ADD	3
#define	SADB_DELETE	4
#define	SADB_GET	5
#define	SADB_ACQUIRE	6
#define	SADB_REGISTER	7
#define	SADB_EXPIRE	8
#define	SADB_FLUSH	9
#define	SADB_DUMP	10   /* not used normally */
#define	SADB_X_PROMISC	11
#define	SADB_X_INVERSE_ACQUIRE	12
#define	SADB_X_UPDATEPAIR	13
#define	SADB_X_DELPAIR		14
#define	SADB_X_DELPAIR_STATE	15
#define	SADB_MAX		15

/*
 * SA flags
 */

#define	SADB_SAFLAGS_PFS	0x1	/* Perfect forward secrecy? */
#define	SADB_SAFLAGS_NOREPLAY	0x2	/* Replay field NOT PRESENT. */

/* Below flags are used by this implementation.  Grow from left-to-right. */
#define	SADB_X_SAFLAGS_USED	0x80000000	/* SA used/not used */
#define	SADB_X_SAFLAGS_UNIQUE	0x40000000	/* SA unique/reusable */
#define	SADB_X_SAFLAGS_AALG1	0x20000000	/* Auth-alg specific flag 1 */
#define	SADB_X_SAFLAGS_AALG2	0x10000000	/* Auth-alg specific flag 2 */
#define	SADB_X_SAFLAGS_EALG1	 0x8000000	/* Encr-alg specific flag 1 */
#define	SADB_X_SAFLAGS_EALG2	 0x4000000	/* Encr-alg specific flag 2 */
#define	SADB_X_SAFLAGS_KM1	 0x2000000	/* Key mgmt. specific flag 1 */
#define	SADB_X_SAFLAGS_KM2	 0x1000000	/* Key mgmt. specific flag 2 */
#define	SADB_X_SAFLAGS_KM3	  0x800000	/* Key mgmt. specific flag 3 */
#define	SADB_X_SAFLAGS_KM4	  0x400000	/* Key mgmt. specific flag 4 */
#define	SADB_X_SAFLAGS_KRES1	  0x200000	/* Reserved by the kernel */
#define	SADB_X_SAFLAGS_NATT_LOC	  0x100000	/* this has a natted src SA */
#define	SADB_X_SAFLAGS_NATT_REM	   0x80000	/* this has a natted dst SA */
#define	SADB_X_SAFLAGS_KRES2	   0x40000	/* Reserved by the kernel */
#define	SADB_X_SAFLAGS_TUNNEL	   0x20000	/* tunnel mode */
#define	SADB_X_SAFLAGS_PAIRED	   0x10000	/* inbound/outbound pair */
#define	SADB_X_SAFLAGS_OUTBOUND	    0x8000	/* SA direction bit */
#define	SADB_X_SAFLAGS_INBOUND	    0x4000	/* SA direction bit */
#define	SADB_X_SAFLAGS_NATTED	    0x1000	/* Local node is behind a NAT */

#define	SADB_X_SAFLAGS_KRES	\
	SADB_X_SAFLAGS_KRES1 | SADB_X_SAFLAGS_KRES2

/*
 * SA state.
 */

#define	SADB_SASTATE_LARVAL		0
#define	SADB_SASTATE_MATURE		1
#define	SADB_SASTATE_DYING		2
#define	SADB_SASTATE_DEAD		3
#define	SADB_X_SASTATE_ACTIVE_ELSEWHERE	4
#define	SADB_X_SASTATE_IDLE		5
#define	SADB_X_SASTATE_ACTIVE		6

#define	SADB_SASTATE_MAX		6

/*
 * SA type.  Gaps are present in the number space because (for the time being)
 * these types correspond to the SA types in the IPsec DOI document.
 */

#define	SADB_SATYPE_UNSPEC	0
#define	SADB_SATYPE_AH		2  /* RFC-1826 */
#define	SADB_SATYPE_ESP		3  /* RFC-1827 */
#define	SADB_SATYPE_RSVP	5  /* RSVP Authentication */
#define	SADB_SATYPE_OSPFV2	6  /* OSPFv2 Authentication */
#define	SADB_SATYPE_RIPV2	7  /* RIPv2 Authentication */
#define	SADB_SATYPE_MIP		8  /* Mobile IPv4 Authentication */

#define	SADB_SATYPE_MAX		8

/*
 * Algorithm types.  Gaps are present because (for the time being) these types
 * correspond to the SA types in the IPsec DOI document.
 *
 * NOTE:  These are numbered to play nice with the IPsec DOI.  That's why
 *	  there are gaps.
 */

/* Authentication algorithms */
#define	SADB_AALG_NONE		0
#define	SADB_AALG_MD5HMAC	2
#define	SADB_AALG_SHA1HMAC	3
#define	SADB_AALG_SHA256HMAC	5
#define	SADB_AALG_SHA384HMAC	6
#define	SADB_AALG_SHA512HMAC	7

#define	SADB_AALG_MAX		7

/* Encryption algorithms */
#define	SADB_EALG_NONE		0
#define	SADB_EALG_DESCBC	2
#define	SADB_EALG_3DESCBC	3
#define	SADB_EALG_BLOWFISH	7
#define	SADB_EALG_NULL		11
#define	SADB_EALG_AES		12
#define	SADB_EALG_AES_CCM_8	14
#define	SADB_EALG_AES_CCM_12	15
#define	SADB_EALG_AES_CCM_16	16
#define	SADB_EALG_AES_GCM_8	18
#define	SADB_EALG_AES_GCM_12	19
#define	SADB_EALG_AES_GCM_16	20
#define	SADB_EALG_MAX		20

/*
 * Extension header values.
 */

#define	SADB_EXT_RESERVED		0

#define	SADB_EXT_SA			1
#define	SADB_EXT_LIFETIME_CURRENT	2
#define	SADB_EXT_LIFETIME_HARD		3
#define	SADB_EXT_LIFETIME_SOFT		4
#define	SADB_EXT_ADDRESS_SRC		5
#define	SADB_EXT_ADDRESS_DST		6
/* These two are synonyms. */
#define	SADB_EXT_ADDRESS_PROXY		7
#define	SADB_X_EXT_ADDRESS_INNER_SRC	SADB_EXT_ADDRESS_PROXY
#define	SADB_EXT_KEY_AUTH		8
#define	SADB_EXT_KEY_ENCRYPT		9
#define	SADB_EXT_IDENTITY_SRC		10
#define	SADB_EXT_IDENTITY_DST		11
#define	SADB_EXT_SENSITIVITY		12
#define	SADB_EXT_PROPOSAL		13
#define	SADB_EXT_SUPPORTED_AUTH		14
#define	SADB_EXT_SUPPORTED_ENCRYPT	15
#define	SADB_EXT_SPIRANGE		16
#define	SADB_X_EXT_EREG			17
#define	SADB_X_EXT_EPROP		18
#define	SADB_X_EXT_KM_COOKIE		19
#define	SADB_X_EXT_ADDRESS_NATT_LOC	20
#define	SADB_X_EXT_ADDRESS_NATT_REM	21
#define	SADB_X_EXT_ADDRESS_INNER_DST	22
#define	SADB_X_EXT_PAIR			23
#define	SADB_X_EXT_REPLAY_VALUE		24
#define	SADB_X_EXT_EDUMP		25
#define	SADB_X_EXT_LIFETIME_IDLE	26
#define	SADB_X_EXT_OUTER_SENS		27

#define	SADB_EXT_MAX			27

/*
 * Identity types.
 */

#define	SADB_IDENTTYPE_RESERVED 0

/*
 * For PREFIX and ADDR_RANGE, use the AF of the PROXY if present, or the SRC
 * if not present.
 */
#define	SADB_IDENTTYPE_PREFIX		1
#define	SADB_IDENTTYPE_FQDN		2  /* Fully qualified domain name. */
#define	SADB_IDENTTYPE_USER_FQDN	3  /* e.g. root@domain.com */
#define	SADB_X_IDENTTYPE_DN		4  /* ASN.1 DER Distinguished Name. */
#define	SADB_X_IDENTTYPE_GN		5  /* ASN.1 DER Generic Name. */
#define	SADB_X_IDENTTYPE_KEY_ID		6  /* Generic KEY ID. */
#define	SADB_X_IDENTTYPE_ADDR_RANGE	7

#define	SADB_IDENTTYPE_MAX 	7

/*
 * Protection DOI values for the SENSITIVITY extension.  There are no values
 * currently, so the MAX is the only non-zero value available.
 */

#define	SADB_DPD_NONE	0

#define	SADB_DPD_MAX	1

/*
 * Diagnostic codes.  These supplement error messages.  Be sure to
 * update libipsecutil's keysock_diag() if you change any of these.
 */

#define	SADB_X_DIAGNOSTIC_PRESET		-1	/* Internal value. */

#define	SADB_X_DIAGNOSTIC_NONE			0

#define	SADB_X_DIAGNOSTIC_UNKNOWN_MSG		1
#define	SADB_X_DIAGNOSTIC_UNKNOWN_EXT		2
#define	SADB_X_DIAGNOSTIC_BAD_EXTLEN		3
#define	SADB_X_DIAGNOSTIC_UNKNOWN_SATYPE	4
#define	SADB_X_DIAGNOSTIC_SATYPE_NEEDED		5
#define	SADB_X_DIAGNOSTIC_NO_SADBS		6
#define	SADB_X_DIAGNOSTIC_NO_EXT		7
/* Bad address family value */
#define	SADB_X_DIAGNOSTIC_BAD_SRC_AF		8
/* in sockaddr->sa_family. */
#define	SADB_X_DIAGNOSTIC_BAD_DST_AF		9
/* These two are synonyms. */
#define	SADB_X_DIAGNOSTIC_BAD_PROXY_AF		10
#define	SADB_X_DIAGNOSTIC_BAD_INNER_SRC_AF	10

#define	SADB_X_DIAGNOSTIC_AF_MISMATCH		11

#define	SADB_X_DIAGNOSTIC_BAD_SRC		12
#define	SADB_X_DIAGNOSTIC_BAD_DST		13

#define	SADB_X_DIAGNOSTIC_ALLOC_HSERR		14
#define	SADB_X_DIAGNOSTIC_BYTES_HSERR		15
#define	SADB_X_DIAGNOSTIC_ADDTIME_HSERR		16
#define	SADB_X_DIAGNOSTIC_USETIME_HSERR		17

#define	SADB_X_DIAGNOSTIC_MISSING_SRC		18
#define	SADB_X_DIAGNOSTIC_MISSING_DST		19
#define	SADB_X_DIAGNOSTIC_MISSING_SA		20
#define	SADB_X_DIAGNOSTIC_MISSING_EKEY		21
#define	SADB_X_DIAGNOSTIC_MISSING_AKEY		22
#define	SADB_X_DIAGNOSTIC_MISSING_RANGE		23

#define	SADB_X_DIAGNOSTIC_DUPLICATE_SRC		24
#define	SADB_X_DIAGNOSTIC_DUPLICATE_DST		25
#define	SADB_X_DIAGNOSTIC_DUPLICATE_SA		26
#define	SADB_X_DIAGNOSTIC_DUPLICATE_EKEY	27
#define	SADB_X_DIAGNOSTIC_DUPLICATE_AKEY	28
#define	SADB_X_DIAGNOSTIC_DUPLICATE_RANGE	29

#define	SADB_X_DIAGNOSTIC_MALFORMED_SRC		30
#define	SADB_X_DIAGNOSTIC_MALFORMED_DST		31
#define	SADB_X_DIAGNOSTIC_MALFORMED_SA		32
#define	SADB_X_DIAGNOSTIC_MALFORMED_EKEY	33
#define	SADB_X_DIAGNOSTIC_MALFORMED_AKEY	34
#define	SADB_X_DIAGNOSTIC_MALFORMED_RANGE	35

#define	SADB_X_DIAGNOSTIC_AKEY_PRESENT		36
#define	SADB_X_DIAGNOSTIC_EKEY_PRESENT		37
#define	SADB_X_DIAGNOSTIC_PROP_PRESENT		38
#define	SADB_X_DIAGNOSTIC_SUPP_PRESENT		39

#define	SADB_X_DIAGNOSTIC_BAD_AALG		40
#define	SADB_X_DIAGNOSTIC_BAD_EALG		41
#define	SADB_X_DIAGNOSTIC_BAD_SAFLAGS		42
#define	SADB_X_DIAGNOSTIC_BAD_SASTATE		43

#define	SADB_X_DIAGNOSTIC_BAD_AKEYBITS		44
#define	SADB_X_DIAGNOSTIC_BAD_EKEYBITS		45

#define	SADB_X_DIAGNOSTIC_ENCR_NOTSUPP		46

#define	SADB_X_DIAGNOSTIC_WEAK_EKEY		47
#define	SADB_X_DIAGNOSTIC_WEAK_AKEY		48

#define	SADB_X_DIAGNOSTIC_DUPLICATE_KMP		49
#define	SADB_X_DIAGNOSTIC_DUPLICATE_KMC		50

#define	SADB_X_DIAGNOSTIC_MISSING_NATT_LOC	51
#define	SADB_X_DIAGNOSTIC_MISSING_NATT_REM	52
#define	SADB_X_DIAGNOSTIC_DUPLICATE_NATT_LOC	53
#define	SADB_X_DIAGNOSTIC_DUPLICATE_NATT_REM	54
#define	SADB_X_DIAGNOSTIC_MALFORMED_NATT_LOC	55
#define	SADB_X_DIAGNOSTIC_MALFORMED_NATT_REM	56
#define	SADB_X_DIAGNOSTIC_DUPLICATE_NATT_PORTS	57

#define	SADB_X_DIAGNOSTIC_MISSING_INNER_SRC	58
#define	SADB_X_DIAGNOSTIC_MISSING_INNER_DST	59
#define	SADB_X_DIAGNOSTIC_DUPLICATE_INNER_SRC	60
#define	SADB_X_DIAGNOSTIC_DUPLICATE_INNER_DST	61
#define	SADB_X_DIAGNOSTIC_MALFORMED_INNER_SRC	62
#define	SADB_X_DIAGNOSTIC_MALFORMED_INNER_DST	63

#define	SADB_X_DIAGNOSTIC_PREFIX_INNER_SRC	64
#define	SADB_X_DIAGNOSTIC_PREFIX_INNER_DST	65
#define	SADB_X_DIAGNOSTIC_BAD_INNER_DST_AF	66
#define	SADB_X_DIAGNOSTIC_INNER_AF_MISMATCH	67

#define	SADB_X_DIAGNOSTIC_BAD_NATT_REM_AF	68
#define	SADB_X_DIAGNOSTIC_BAD_NATT_LOC_AF	69

#define	SADB_X_DIAGNOSTIC_PROTO_MISMATCH	70
#define	SADB_X_DIAGNOSTIC_INNER_PROTO_MISMATCH	71

#define	SADB_X_DIAGNOSTIC_DUAL_PORT_SETS	72

#define	SADB_X_DIAGNOSTIC_PAIR_INAPPROPRIATE	73
#define	SADB_X_DIAGNOSTIC_PAIR_ADD_MISMATCH	74
#define	SADB_X_DIAGNOSTIC_PAIR_ALREADY		75
#define	SADB_X_DIAGNOSTIC_PAIR_SA_NOTFOUND	76
#define	SADB_X_DIAGNOSTIC_BAD_SA_DIRECTION	77

#define	SADB_X_DIAGNOSTIC_SA_NOTFOUND		78
#define	SADB_X_DIAGNOSTIC_SA_EXPIRED		79
#define	SADB_X_DIAGNOSTIC_BAD_CTX		80
#define	SADB_X_DIAGNOSTIC_INVALID_REPLAY	81
#define	SADB_X_DIAGNOSTIC_MISSING_LIFETIME	82

#define	SADB_X_DIAGNOSTIC_BAD_LABEL		83
#define	SADB_X_DIAGNOSTIC_MAX			83

/* Algorithm type for sadb_x_algdesc above... */

#define	SADB_X_ALGTYPE_NONE		0
#define	SADB_X_ALGTYPE_AUTH		1
#define	SADB_X_ALGTYPE_CRYPT		2
#define	SADB_X_ALGTYPE_COMPRESS		3

#define	SADB_X_ALGTYPE_MAX		3

/* Key management protocol for sadb_x_kmc above... */

#define	SADB_X_KMP_MANUAL	0	/* Cookie is ignored. */
#define	SADB_X_KMP_IKE		1
#define	SADB_X_KMP_KINK		2

#define	SADB_X_KMP_MAX		2

/*
 * Handy conversion macros.  Not part of the PF_KEY spec...
 */

#define	SADB_64TO8(x)	((x) << 3)
#define	SADB_8TO64(x)	((x) >> 3)
#define	SADB_8TO1(x)	((x) << 3)
#define	SADB_1TO8(x)	((x) >> 3)

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_PFKEYV2_H */
