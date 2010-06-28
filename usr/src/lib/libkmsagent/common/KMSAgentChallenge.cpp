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
 * \file KMSAgentChallenge.cpp
 */

#include "KMSAgentChallenge.h"
#include "KMSAgentCryptoUtilities.h"
#include "KMSAgentStringUtilities.h"
#include "ApplianceParameters.h"
#include "SYSCommon.h"

extern "C" int Log2(char* msg1,
                    char* msg2);

#ifdef METAWARE
#include "debug.h"
#endif


/**
 *  ComputeChallengeResponse
 */
bool ComputeChallengeResponse(
   const unsigned char* i_pAuthenticationSecret,
   int i_iAuthenticationSecretLength,
   const unsigned char* i_pRootCACertificate,
   int i_iRootCACertificateLength,
   const unsigned char* i_pAuthenticationChallenge,
   int i_iAuthenticationChallengeLength,
   unsigned char* o_pAuthenticationChallengeResponse,
   int i_iAuthenticationChallengeResponseLength )
{

   bool rc;
   
#ifdef DEBUG
   Log2 ("KMSAgent_LoadProfile::ComputeChallengeResponse", "Entered");
#endif    
   FATAL_ASSERT( i_iAuthenticationChallengeResponseLength == HMAC_LENGTH );
   
   // challenge response is HMAC-SHA1( RootCACertificate ||
   // AuthenticationChallenge, AuthenticationSecret )
   const unsigned char* aBuffersToHMAC[2];
   int aBuffersToHMACSize[2];
   
   aBuffersToHMAC[0]     = i_pRootCACertificate;
   aBuffersToHMACSize[0] = i_iRootCACertificateLength;
   
   aBuffersToHMAC[1]     = i_pAuthenticationChallenge;
   aBuffersToHMACSize[1] = i_iAuthenticationChallengeLength;

   rc = HMACBuffers(
      2,
      aBuffersToHMAC, 
      aBuffersToHMACSize, 
      i_pAuthenticationSecret, 
      i_iAuthenticationSecretLength, 
      o_pAuthenticationChallengeResponse );

#if defined(METAWARE) && defined(DEBUG)
   int j=0;

   j+=snprintf(outmsg+j, OUTMSG_SIZE, 
              "length=%x\n",
              i_iAuthenticationSecretLength);
   
   for (int i=0 ; i< i_iAuthenticationSecretLength; i++)
   {
      j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
                 "%x",
                 i_pAuthenticationSecret[i]);
   }
   snprintf(outmsg+j,  OUTMSG_SIZE, "\n");
   
   Log2("Secret = ",outmsg);
#endif
   
#if defined(METAWARE) && defined(DEBUG)
   j=0;
   
   j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
              "length=%x\n",
              i_iRootCACertificateLength);
   
   for (i=0 ; i< i_iRootCACertificateLength; i++)
   {
      j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
                 "%x",
                 i_pRootCACertificate[i]);
   }
   snprintf(outmsg+j, OUTMSG_SIZE, "\n");
   
   Log2("i_pRootCACertificate = ",outmsg);
#endif
   
#if defined(METAWARE) && defined(DEBUG)
   j=0;
   
   j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
              "length=%x\n",
              i_iAuthenticationChallengeLength);
   
   for (i=0 ; i< i_iAuthenticationChallengeLength; i++)
   {
      j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
                 "%x",
                 i_pAuthenticationChallenge[i]);
   }
   snprintf(outmsg+j,  OUTMSG_SIZE, "\n");
   
   Log2("i_pAuthenticationChallenge = ",outmsg);
#endif
   
#if defined(METAWARE) && defined(DEBUG)
   j=0;
   
   j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
              "length=%x\n",
              i_iAuthenticationChallengeResponseLength);
   
   for (i=0 ; i< i_iAuthenticationChallengeResponseLength; i++)
   {
      j+=snprintf(outmsg+j,  OUTMSG_SIZE, 
                 "%x",
                 o_pAuthenticationChallengeResponse[i]);
   }
   snprintf(outmsg+j,  OUTMSG_SIZE, "\n");
   
   Log2("o_pAuthenticationChallengeResponse = ",outmsg);
#endif
   
   return rc;
   
#undef __IAM__
}

/**
 *   ComputeEntityHashedPassphraseAndAuthenticationSecret
 */
bool ComputeEntityHashedPassphraseAndAuthenticationSecret(
        const char* i_sPassphrase,
        char* const o_sHexHashedPassphrase,
        int* const  o_piAuthenticationHashIterationCount,
        char* const o_sHexAuthenticationSecret )
{
    // HashedPassphrase is SHA1( Passphrase-UTF-8 )
    // Using UTF-8 ensures the same result on different platforms with
    // different wide character representations.
    // This hashed passphrase value is used to wrap entity
    // private key materials.
#if defined(METAWARE) && defined(DEBUG)
    Log2 ("KMSAgent_LoadProfile::ComputeEntityHashedPassphraseAndAuthenticationSecret", 
          "Entered");
#endif    

    unsigned char aHashedPassphrase[HASH_LENGTH];

    memset(aHashedPassphrase, 0, HASH_LENGTH);

    if ( strlen(i_sPassphrase) > 0 )
    {
        if ( !HashBuffer(
                    (unsigned char*)i_sPassphrase, 
                    strlen(i_sPassphrase),
                    aHashedPassphrase) )
        {
            return false;
        }
    }

    ConvertBinaryToUTF8HexString( o_sHexHashedPassphrase, 
                                  aHashedPassphrase, 
                                  HASH_LENGTH );

    // HexAuthenticationSecret is SHA1( SHA1( ... ( SHA1(
    // HashedPassphrase ) ) ) The number of iterations is time bounded
    // at 1/10 of a second, and also bounded by fixed minimum and
    // maximum values (to prevent too weak of a computation and to
    // prevent a DoS, respectively).  This value is used as the shared
    // secret in challenge-response authentication exchanges.

    *o_piAuthenticationHashIterationCount = 0;
    
    unsigned long iStartTickCount = K_GetTickCount();
    
    while ( *o_piAuthenticationHashIterationCount < 
            MAX_AUTHENTICATION_ITERATION_COUNT
            && ( *o_piAuthenticationHashIterationCount < 
                 MIN_AUTHENTICATION_ITERATION_COUNT
                 || iStartTickCount + 
                 AUTHENTICATION_ITERATION_TIME_IN_MILLISECONDS > 
                 K_GetTickCount() ) )
    {
       if ( !HashBuffer(
               aHashedPassphrase, 
               HASH_LENGTH,
               aHashedPassphrase) )
       {
          return false;
       }
       
       (*o_piAuthenticationHashIterationCount)++;
    }
    
    ConvertBinaryToUTF8HexString( o_sHexAuthenticationSecret, 
                                  aHashedPassphrase, HASH_LENGTH );

#if defined(METAWARE) && defined(DEBUG)
    snprintf(outmsg,  OUTMSG_SIZE, 
            "o_sHexAuthenticationSecret=%x o_piAuth..."
            "= %x aHashedPassphrase=%s\n", 
            o_sHexAuthenticationSecret, 
            *o_piAuthenticationHashIterationCount,
            aHashedPassphrase);
    Log2("ComputeEntityHashedPassphraseAndAuthenticationSecret ",
         outmsg);
#endif

    return true;
}

/**
 *   ComputeFixedEntityHashedPassphraseAndAuthenticationSecret
 */
bool ComputeFixedEntityHashedPassphraseAndAuthenticationSecret(
   const char* i_sPassphrase,
   char* const o_sHexHashedPassphrase,
   int         i_iAuthenticationHashIterationCount,
   char* const o_sHexAuthenticationSecret )
{
   // compute same values as
   // ComputeEntityHashedPassphraseAndAuthenticationSecret, except
   // iteration count is fixed
#if defined(METAWARE) && defined(DEBUG)
    Log2 ("KMSAgent_LoadProfile::"
          "ComputeFixedEntityHashedPassphraseAndAuthenticationSecret", "Entered");
#endif    
   
   // detect attempts to cause weak computation or DoS attack
   if ( i_iAuthenticationHashIterationCount < 
        MIN_AUTHENTICATION_ITERATION_COUNT   || 
        i_iAuthenticationHashIterationCount > 
        MAX_AUTHENTICATION_ITERATION_COUNT )
   {
      return false;
   }


   unsigned char aHashedPassphrase[HASH_LENGTH];

   memset(aHashedPassphrase, 0, HASH_LENGTH);

   if ( strlen(i_sPassphrase) > 0 )
   {
      if ( !HashBuffer(
              (unsigned char*)i_sPassphrase, 
              strlen(i_sPassphrase),
              aHashedPassphrase) )
      {
         return false;
      }
   }

   ConvertBinaryToUTF8HexString( o_sHexHashedPassphrase, 
                                 aHashedPassphrase, HASH_LENGTH );

   int i;
   for ( i = 0; i < i_iAuthenticationHashIterationCount; i++ )
   {
      if ( !HashBuffer(
              aHashedPassphrase, 
              HASH_LENGTH,
              aHashedPassphrase) )
      {
         return false;
      }
   }

   ConvertBinaryToUTF8HexString( o_sHexAuthenticationSecret, 
                                 aHashedPassphrase, HASH_LENGTH );

#if defined(METAWARE) && defined(DEBUG)
    snprintf(outmsg,  OUTMSG_SIZE, 
            "i_iAuth %x \n",
            i_iAuthenticationHashIterationCount);
    
    Log2("ComputeEntityHashedPassphraseAndAuthenticationSecret ",
         outmsg);
#endif


   return true;
}
