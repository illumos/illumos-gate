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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * \file KMSAgentAESKeyWrap.h
 */

#ifndef KMSAgentAESKeyWrap_H
#define KMSAgentAESKeyWrap_H

#ifdef WIN32
#include <string.h>
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * AES Key Wrap (see RFC 3394). No logging is performed since this
     *  functions must execute in a Known Answer Test prior to 
     *  #KMSAgent_InitializeLibrary.
     *  @param  kek  The AES symmetric key-encryption key
     *  @param  kek_len The size, in bytes, of the KEK
     *  @param  pt  The plain text key to be AES key wrapped
     *  @param  len The "n" parameter from RFC3394, i.e. the number of 64-bit key data
     *          blocks.  For example, with 256 bit plain text keys n=4.
     *  @param  ct  The resulting AES wrapped key.  The size of ct needs to allow
     *          for the 64-bit integrity check  value, i.e. sizeof(pt+8)
     */
    void aes_key_wrap (const uint8_t *kek,
                       size_t kek_len,
                       const uint8_t *pt,
                       size_t len,
                       uint8_t *ct);

    /**
     * AES Key Unwrap (see RFC 3394). No logging is performed since this
     *  functions must execute in a Known Answer Test prior to 
     *  #KMSAgent_InitializeLibrary.
     *  @param  kek  The AES symmetric key-encryption key
     *  @param  kek_len The size, in bytes, of the KEK
     *  @param  ct  The AES wrapped key.
     *  @param  pt  The resulting, unwrapped, plain text key.
     *  @param  len The "n" parameter from RFC3394, i.e. the number of 64-bit key data
     *          blocks.  For example, with 256 bit plain text keys n=4.
     *  @return 0 on success, non-zero otherwise
     */
    int aes_key_unwrap (const uint8_t *kek,
                        size_t kek_len,
                        const uint8_t *ct,
                        uint8_t *pt,
                        size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KMSAgentAESKeyWrap_H */
