/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BLOWFISH_CBC_CRYPT_H
#define	_BLOWFISH_CBC_CRYPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/crypto/common.h>
#include "blowfish_impl.h"

/*
 * bc_keysched:		Pointer to key schedule.
 *
 * bc_keysched_len:	Length of the key schedule.
 *
 * bc_remainder:	This is for residual data, i.e. data that can't
 *			be processed because there are too few bytes.
 *			Must wait until more data arrives.
 *
 * bc_remainder_len:	Number of bytes in bc_remainder.
 *
 * bc_iv:		Scratch buffer that sometimes contains the IV.
 *
 * bc_lastblock:	Scratch buffer.
 *
 * bc_lastp:		Pointer to previous block of ciphertext.
 *
 * bc_copy_to:		Pointer to where encrypted residual data needs
 *			to be copied.
 *
 * bc_flags:		BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE
 *			When a context is freed, it is necessary
 *			to know whether the key schedule was allocated
 *			by the caller, or by blowfish_common_init().
 *			If allocated by the latter, then it needs to be freed.
 *
 *			BLOWFISH_CBC_MODE
 *			If flag is not set, the mode is BLOWFISH_ECB_MODE.
 *
 */
typedef struct blowfish_ctx {
	void *bc_keysched;
	size_t bc_keysched_len;
	uint64_t bc_iv;
	uint64_t bc_lastblock;
	uint64_t bc_remainder;
	size_t bc_remainder_len;
	uint8_t *bc_lastp;
	uint8_t *bc_copy_to;
	uint32_t bc_flags;
} blowfish_ctx_t;

#define	BLOWFISH_PROVIDER_OWNS_KEY_SCHEDULE	0x00000001
#define	BLOWFISH_CBC_MODE			0x00000002

extern int blowfish_encrypt_contiguous_blocks(blowfish_ctx_t *, char *,
    size_t, crypto_data_t *);
extern int blowfish_decrypt_contiguous_blocks(blowfish_ctx_t *, char *,
    size_t, crypto_data_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _BLOWFISH_CBC_CRYPT_H */
