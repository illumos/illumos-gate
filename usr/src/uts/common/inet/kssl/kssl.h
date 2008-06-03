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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_KSSL_KSSL_H
#define	_INET_KSSL_KSSL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/crypto/common.h>

/* These are re-definition from <crypto/ioctl.h>  */
typedef struct kssl_object_attribute {
	uint64_t	ka_type;		/* attribute type */
	uint32_t	ka_value_offset;	/* offset to attribute value */
	uint32_t	ka_value_len;		/* length of attribute value */
} kssl_object_attribute_t;

typedef struct kssl_key {
	crypto_key_format_t ks_format;	/* format identifier */
	uint32_t ks_count;		/* number of attributes */
	uint32_t ks_attrs_offset;	/* offset to the attributes */
} kssl_key_t;

typedef struct kssl_certs_s {
	uint32_t sc_count;		/* number of certificates */
	uint32_t sc_sizes_offset;	/* offset to certificates sizes array */
	uint32_t sc_certs_offset;	/* offset to certificates array */
} kssl_certs_t;

#define	MAX_PIN_LENGTH			1024

typedef struct kssl_tokinfo_s {
	uint8_t toklabel[CRYPTO_EXT_SIZE_LABEL];
	uint32_t pinlen;
	uint32_t tokpin_offset;		/* offset to the pin */
	uint32_t ck_rv;			/* PKCS #11 specific error */
} kssl_tokinfo_t;

#define	SSL_RSA_WITH_NULL_SHA		0x0002
#define	SSL_RSA_WITH_RC4_128_MD5	0x0004
#define	SSL_RSA_WITH_RC4_128_SHA	0x0005
#define	SSL_RSA_WITH_DES_CBC_SHA	0x0009
#define	SSL_RSA_WITH_3DES_EDE_CBC_SHA	0x000a
#define	TLS_RSA_WITH_AES_128_CBC_SHA	0x002f
#define	TLS_RSA_WITH_AES_256_CBC_SHA	0x0035
#define	CIPHER_SUITE_COUNT		7
#define	CIPHER_NOTSET			0xffff

#define	DEFAULT_SID_TIMEOUT		86400	/* 24 hours in seconds */
#define	DEFAULT_SID_CACHE_NENTRIES	5000

typedef struct kssl_params_s {
	uint64_t		kssl_params_size; /* total params buf len */
	/* address and port number */
	struct sockaddr_in	kssl_addr;
	uint16_t		kssl_proxy_port;

	uint32_t		kssl_session_cache_timeout;	/* In seconds */
	uint32_t		kssl_session_cache_size;

	/*
	 * Contains ordered list of cipher suites. We do not include
	 * the one suite with no encryption. Hence the -1.
	 */
	uint16_t		kssl_suites[CIPHER_SUITE_COUNT - 1];

	uint8_t			kssl_is_nxkey;
	kssl_tokinfo_t		kssl_token;

	/* certificates */
	kssl_certs_t		kssl_certs;

	/* private key */
	kssl_key_t		kssl_privkey;
} kssl_params_t;

/* The ioctls to /dev/kssl */
#define	KSSL_IOC(x)		(('s' << 24) | ('s' << 16) | ('l' << 8) | (x))
#define	KSSL_ADD_ENTRY		KSSL_IOC(1)
#define	KSSL_DELETE_ENTRY	KSSL_IOC(2)

#ifdef	_KERNEL

extern int kssl_add_entry(kssl_params_t *);
extern int kssl_delete_entry(struct sockaddr_in *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _INET_KSSL_KSSL_H */
