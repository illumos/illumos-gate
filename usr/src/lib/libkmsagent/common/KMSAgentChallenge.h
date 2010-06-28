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
 * \file KMSAgentChallenge.h
 */

#ifndef KMSAagentChallenge_H
#define	KMSAagentChallenge_H

/**
 *   computes the response to the KMA's challenge using
 *   HMAC-SHA1( RootCACertificate || AuthenticationChallenge,
 *      AuthenticationSecret ).  The AuthenticationSecret is
 *   used as the key in the HMAC-SHA1 computation.
 *
 *   @param i_pAuthenticationSecret
 *   @param i_iAuthenticationSecretLength
 *   @param i_pRootCACertificate
 *   @param i_iRootCACertificateLength
 *   @param i_pAuthenticationChallenge
 *   @param i_iAuthenticationChallengeLength
 *   @param o_pAuthenticationChallengeResponse
 *   @param i_iAuthenticationChallengeResponseLength
 *
 *   @return boolean success indicator
 */
bool ComputeChallengeResponse(
        const unsigned char* i_pAuthenticationSecret,
        int i_iAuthenticationSecretLength,
        const unsigned char* i_pRootCACertificate,
        int i_iRootCACertificateLength,
        const unsigned char* i_pAuthenticationChallenge,
        int i_iAuthenticationChallengeLength,
        unsigned char* o_pAuthenticationChallengeResponse,
        int i_iAuthenticationChallengeResponseLength );

/**
 *  computes the SHA1 hash of the specified passphrase.
 *  The number of SHA1 iterations
 *  is recorded in <code>o_iAuthenticationHashIterationCount</code> and the result
 *  stored in o_sHexAuthenticationSecret as a UTF8 hex string.
 *  HexAuthenticationSecret is SHA1( SHA1( ... ( SHA1( HashedPassphrase ) ) )
 *  The number of iterations is time bounded at 1/10 of a second, and also
 *  bounded by fixed minimum and maximum values (to prevent too weak of a
 *  computation and to prevent a DoS, respectively).
 *  This value is used as the shared secret in challenge-response
 *  authentication exchanges.
 
 *  @param i_sPassphrase            the passphrase to be hashed
 *  @param o_sHexHashedPassphrase   the hashed passphrase
 *                                  returned in UTF8 hexadecimal, this
 *                                  buffer should be at least
 *                                  2*HASH_LENGTH+1 bytes
 *  @param o_iAuthenticationHashIterationCount
 *  @param o_sHexAuthenticationSecret
 *
 *  @return boolean success indicator
 */
bool ComputeEntityHashedPassphraseAndAuthenticationSecret(
   const char* const   i_sPassphrase,
   char* const         o_sHexHashedPassphrase,
   int* const          o_piAuthenticationHashIterationCount,
   char* const         o_sHexAuthenticationSecret );

/**
 *  computes the SHA1 hash of the specified passphrase.  The SHA1 is
 *  performed a "fixed" number of times as specified by
 *   <code>i_iAuthenticationHashIterationCount</code>.
 *
 *  @param i_sPassphrase  the passprhase to be SHA1 hashed 
 *  @param o_sHexHashedPassphrase the SHA1 hash
 *            of i_sPassphrase stored as a UTF8 hex string
 *  @param i_iAuthenticationHashIterationCount the number
 *            of times to SHA1 hash the passphrase
 *  @param o_sHexAuthenticationSecret the passphrase hashed
 *            the fixed number of times and stored as a UTF8
 *            hex string
 *
 *  @return boolean success indicator
 */
bool ComputeFixedEntityHashedPassphraseAndAuthenticationSecret(
   const char* i_sPassphrase,
   char* const o_sHexHashedPassphrase,
   int         i_iAuthenticationHashIterationCount,
   char* const o_sHexAuthenticationSecret );

#endif	/* KMSAagentChallenge_H */

