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

/**
 * \file KMSAgentCryptoUtilities.cpp
 */

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "KMSAgentCryptoUtilities.h"
#include "SYSCommon.h"
#include "KMSAgentStringUtilities.h"
//#include "ApplianceParameters.h"

// Find header in CryptoUtilities.h
bool GetPseudorandomBytes(
        int i_iNumBytes,
        unsigned char* o_pBytes )
{
    if ( 1 != RAND_bytes( o_pBytes, i_iNumBytes) )
    {
        return false;
    }

    return true;
}

// assumes o_pHashedBuffer points to HASH_LENGTH bytes
bool HashBuffer( 
        const unsigned char* i_pBufferToHash,
        int i_iBufferToHashSize,
        unsigned char* o_pHashedBuffer )
{

    FATAL_ASSERT( HASH_LENGTH == SHA_DIGEST_LENGTH );
    FATAL_ASSERT( i_pBufferToHash && (i_iBufferToHashSize > 0) && o_pHashedBuffer );

    unsigned char aDigest[HASH_LENGTH];

    if ( NULL == SHA1( i_pBufferToHash, i_iBufferToHashSize, aDigest ) )
    {
        return false;
    }

    memcpy( o_pHashedBuffer, aDigest, HASH_LENGTH );

    return true;
}

// assumes o_pHMACBuffer points to HMAC_LENGTH bytes
bool HMACBuffers(
        int i_iBufferCount,
        const unsigned char** i_pBufferToHMAC,
        int* i_pBufferToHMACSize,
        const unsigned char* i_pHMACKey,
        int i_iHMACKeySize,
        unsigned char* o_pHMACBuffer )
{
    // assumes o_pHMACBuffer points to HMAC_LENGTH bytes

    FATAL_ASSERT( HMAC_LENGTH == SHA_DIGEST_LENGTH );
    FATAL_ASSERT( (i_iBufferCount > 0) && 
                    i_pBufferToHMAC && 
                    i_pBufferToHMACSize && 
                    i_pHMACKey && 
                    (i_iHMACKeySize > 0) && o_pHMACBuffer );

    HMAC_CTX stContext;

    HMAC_CTX_init( &stContext );

    HMAC_Init_ex( &stContext, i_pHMACKey, i_iHMACKeySize, EVP_sha1(), NULL );

    int i;
    for ( i = 0; i < i_iBufferCount; i++ )
    {
        HMAC_Update( &stContext, i_pBufferToHMAC[i], i_pBufferToHMACSize[i] );
    }

    unsigned int iHMACSize = HMAC_LENGTH;

    HMAC_Final( &stContext, o_pHMACBuffer, &iHMACSize );

    FATAL_ASSERT( iHMACSize == HMAC_LENGTH );

    HMAC_CTX_cleanup( &stContext );

    return true;
}

