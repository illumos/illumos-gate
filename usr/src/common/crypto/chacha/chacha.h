/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.
 */

#ifndef _CHACHA_H
#define	_CHACHA_H

/*
 * ChaCha cipher implementation header
 *
 * Note, the chacha C files that we have, have a compile time option for
 * generating a keystream only. eg. in other words -DKEYSTREAM_ONLY. If using
 * chacha, for something like arc4random, where you aren't doing encryption,
 * then you should pass -DKEYSTREAM_ONLY. If encryption is being done, then it
 * should not be defined. The main difference is basically doing another pass
 * over the data and xoring it with the generated cipher.
 */

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct chacha_ctx {
	uint32_t chacha_input[16];
} chacha_ctx_t;

extern void chacha_keysetup(chacha_ctx_t *, const uint8_t *, uint32_t,
    uint32_t);
extern void chacha_ivsetup(chacha_ctx_t *, const uint8_t *);
extern void chacha_encrypt_bytes(chacha_ctx_t *, const uint8_t *, uint8_t *,
    uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _CHACHA_H */
