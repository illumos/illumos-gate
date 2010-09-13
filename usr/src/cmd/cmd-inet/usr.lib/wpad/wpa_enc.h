/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */
#ifndef __WPA_ENC_H
#define	__WPA_ENC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <openssl/sha.h>
#include <openssl/md5.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SHA1_MAC_LEN	SHA_DIGEST_LENGTH
#define	MD5_MAC_LEN	MD5_DIGEST_LENGTH

void aes_wrap(uint8_t *, int, uint8_t *, uint8_t *);
int aes_unwrap(uint8_t *, int, uint8_t *, uint8_t *);

void hmac_sha1_vector(unsigned char *, unsigned int,
    size_t, unsigned char *[], unsigned int *, unsigned char *);

void hmac_sha1(unsigned char *, unsigned int,
    unsigned char *, unsigned int, unsigned char *);

void sha1_prf(unsigned char *, unsigned int,
    char *, unsigned char *, unsigned int, unsigned char *, size_t);

void pbkdf2_sha1(char *, char *, size_t, int, unsigned char *, size_t);

void rc4_skip(uint8_t *, size_t, size_t, uint8_t *, size_t);
void rc4(uint8_t *, size_t, uint8_t *, size_t);

void hmac_md5_vector(uint8_t *, size_t, size_t,
    uint8_t *[], size_t *, uint8_t *);
void hmac_md5(uint8_t *, size_t, uint8_t *, size_t, uint8_t *);

#ifdef __cplusplus
}
#endif

#endif /* __WPA_ENC_H */
