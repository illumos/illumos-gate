/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IPHADA_H
#define	_SYS_IPHADA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DA_ICV_MAX_LEN	128		/* max ICV length [bytes] */

/*
 * iphada.h header for IP Hardware Acceleration Data Attributes
 *
 *   This is a contract private interface for use by the Sun
 *   Hardware Accelerated Ethernet driver ONLY.
 */
typedef struct da_ipsec {
	int		da_type;	/* M_CTL message ident */
	int		da_flag;
	uint32_t	da_icv_len;	/* da_icv length in bytes */
	uchar_t		da_icv[DA_ICV_MAX_LEN];	/* ICV for AH or ESP+auth */
} da_ipsec_t;

#define	IPHADA_M_CTL    0xA1D53DE5u

/*
 * IPSec algorithms capabilities (cip_data in dl_capab_ipsec_t)
 */
typedef struct {
	t_uscalar_t	alg_type;
	t_uscalar_t	alg_prim;	/* algorithm primitive */
	t_uscalar_t	alg_thruput;	/* approx throughput metric in Mb/s */
	t_uscalar_t	alg_flag;	/* flags */
	t_uscalar_t	alg_minbits;	/* minimum key len in bits */
	t_uscalar_t	alg_maxbits;	/* maximum key len in bits */
	t_uscalar_t	alg_incrbits;	/* key len increment in bits */
} dl_capab_ipsec_alg_t;

/*
 * IPSec sub-capability (follows dl_capability_sub_t)
 */
typedef struct {
	t_uscalar_t		cip_version;	/* interface version */
	t_uscalar_t		cip_nciphers;	/* number ciphers supported */
	dl_capab_ipsec_alg_t	cip_data[1];	/* data */
} dl_capab_ipsec_t;

/*
 * Algorithm types (alg_type field of dl_capab_ipsec_alg_t)
 */
#define	DL_CAPAB_IPSEC_ALG_AUTH		0x01	/* authentication alg. */
#define	DL_CAPAB_IPSEC_ALG_ENCR		0x02	/* encryption alg. */

/* alg_prim ciphers */
#define	DL_CAPAB_IPSEC_ENCR_DES		0x02
#define	DL_CAPAB_IPSEC_ENCR_3DES	0x03
#define	DL_CAPAB_IPSEC_ENCR_BLOWFISH	0x07
#define	DL_CAPAB_IPSEC_ENCR_NULL	0x0b	/* no encryption */
#define	DL_CAPAB_IPSEC_ENCR_AES		0x0c

/* alg_prim authentications */
#define	DL_CAPAB_IPSEC_AUTH_NONE	0x00	/* no authentication */
#define	DL_CAPAB_IPSEC_AUTH_MD5HMAC	0x02
#define	DL_CAPAB_IPSEC_AUTH_SHA1HMAC	0x03

/* alg_flag values */
#define	DL_CAPAB_ALG_ENABLE	0x01	/* enable this algorithm */

/*
 * For DL_CT_IPSEC_AH and DL_CT_IPSEC_ESP, the optional dl_key data
 * that follows the dl_control_req_t or dl_control_ack_t will be the IPsec
 * SPI (Security Parameters Index) value and the destination address.
 * This is defined as being unique per protocol.
 */

#define	DL_CTL_IPSEC_ADDR_LEN	16	/* IP addr length in bytes */

typedef struct dl_ct_ipsec_key {
	uint32_t dl_key_spi;		/* Security Parameters Index value */
	uchar_t dl_key_dest_addr[DL_CTL_IPSEC_ADDR_LEN]; /* dest IP address */
	uint32_t dl_key_addr_family; 	/* family of dest IP address */
					/* (AF_INET or AF_INET6) */
} dl_ct_ipsec_key_t;

#define	DL_CT_IPSEC_MAX_KEY_LEN	512	/* max key length in bytes */

/*
 * Possible flags for sadb_sa_flags.
 */
#define	DL_CT_IPSEC_INBOUND	0x01	/* SA can be used for inbound pkts */
#define	DL_CT_IPSEC_OUTBOUND	0x02	/* SA can be used for outbound pkts */

/*
 * minimal SADB entry content
 * fields are defined as per RFC 2367 and <net/pfkeyv2.h>
 * This defines the content and format of the dl_data portion of
 * the dl_control_req_t or dl_control_ack_t.
 */
typedef struct dl_ct_ipsec {
	uint8_t sadb_sa_auth;			/* Authentication algorithm */
	uint8_t sadb_sa_encrypt;		/* Encryption algorithm */
	uint32_t sadb_sa_flags;			/* SA flags. */
	uint16_t sadb_key_len_a;		/* auth key length in bytes */
	uint16_t sadb_key_bits_a;		/* auth key length in bits */
	uint16_t sadb_key_data_a[DL_CT_IPSEC_MAX_KEY_LEN];	/* key data */
	uint16_t sadb_key_len_e;		/* encr key length in bytes */
	uint16_t sadb_key_bits_e;		/* encr key length in bits */
	uint16_t sadb_key_data_e[DL_CT_IPSEC_MAX_KEY_LEN];	/* key data */
} dl_ct_ipsec_t;



#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IPHADA_H */
