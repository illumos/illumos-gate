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
 * \file KMSAgentKnownAnswerTests.cpp
 */

#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
#include <aes_impl.h>
#define AES_MAXKEYBYTES AES_MAX_KEY_BYTES
#define	AES_MAXKEYBITS AES_MAXBITS
#else
#include "rijndael.h"
#endif
#include "KMSAgentCryptoUtilities.h"
#include "KMSAgentStringUtilities.h"

#ifdef METAWARE
#include "debug.h"
#include "sizet.h"
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#endif

#include "KMSAgentAESKeyWrap.h"
#include "KMSAgentKnownAnswerTests.h"

int KnownAnswerTestAESKeyWrap (void)
{

    /* 
     * Test Vectors from RFC3394 for 256 bit KEK and 256 bit Key
     *  Wrap  Input:
           KEK:
             000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
           Key Data:
             00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F

           Output:
           Ciphertext  28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326
                       CBC7F0E71A99F43B FB988B9B7A02DD21

           Unwrap:
           Plaintext  A6A6A6A6A6A6A6A6 0011223344556677 8899AABBCCDDEEFF
                      0001020304050607 08090A0B0C0D0E0F

           Output:
           Key Data:
                00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F

     */

    static char sKEK[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    static char sKey[] = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    static char sKnownCiphertext[] = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";

    //#ifdef KAT_DEBUG
    //    printf("\nAES Key Wrap Test using Test Vectors from RFC 3394 for 256b KEK and 256b Key\n\n");
    //    printf("KEK=%s\n", sKEK);
    //    printf("Key=%s\n", sKey);
    //#endif

    // key-encryption key
    unsigned char acKEK[AES_MAXKEYBYTES];

    // plaintext key
    unsigned char acKey[AES_MAXKEYBYTES];

    // the wrapped key includes an extra 64bits for the integrity check register
    unsigned char acWrappedKey[AES_MAXKEYBYTES + 8];
    unsigned char acUnWrappedKey[AES_MAXKEYBYTES];
    unsigned char acExpectedWrappedKey[AES_MAXKEYBYTES + 8];

    if ((size_t) ConvertUTF8HexStringToBinary(
        sKnownCiphertext,
        acExpectedWrappedKey) != strlen(sKnownCiphertext) / 2)
    {
        return -1;
    }

    if (ConvertUTF8HexStringToBinary(
        sKEK,
        acKEK) != AES_MAXKEYBYTES)
    {
        return -1;
    }

    if (ConvertUTF8HexStringToBinary(
        sKey,
        acKey) != AES_MAXKEYBYTES)
    {
        return -1;
    }

    // for 256 bit Key n=64
    aes_key_wrap(acKEK, sizeof (acKEK), acKey,
            4, acWrappedKey);

    if (memcmp(acWrappedKey, acExpectedWrappedKey, sizeof (acWrappedKey)) != 0)
    {
        return -1;
    }

    if (aes_key_unwrap(acKEK, sizeof (acKEK), acWrappedKey,
        acUnWrappedKey, 4) != 0)
    {
        return -1;
    }

    if (memcmp(acKey, acUnWrappedKey, sizeof (acKey)) != 0)
    {
        return -1;
    }

    return 0;
}

static int AES_ECB_TestExecution (
                                  const char * const i_sPlainText, 
                                  const char * const i_sKnownCypherText, 
                                  const unsigned char * const i_pKey)
{
    unsigned char acPlainText[256];
    unsigned char acCypherText[sizeof (acPlainText)];
    unsigned char acKnownCypherText[sizeof (acPlainText)];
    unsigned char acDecryptedCypherText[sizeof (acPlainText)];
    memset(acDecryptedCypherText, 0, sizeof (acDecryptedCypherText));

#ifdef KAT_DEBUG    
    char sComputedCypherText[256];
#endif
    
#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
    void *ks;
    size_t ks_size;
#else
    rijndael_ctx ctx;
#endif

    if ((size_t) ConvertUTF8HexStringToBinary(
        i_sPlainText,
        acPlainText) != strlen(i_sPlainText) / 2)
    {
        return -1;
    }
    if ((size_t) ConvertUTF8HexStringToBinary(
        i_sKnownCypherText,
        acKnownCypherText) != strlen(i_sKnownCypherText) / 2)
    {
        return -1;
    }
    
#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
	ks = aes_alloc_keysched(&ks_size, 0);
	if (ks == NULL)
		return (-1);
	aes_init_keysched(i_pKey, AES_MAXKEYBITS, ks);
	(void) aes_encrypt_block(ks, acPlainText, acCypherText);
#else
    rijndael_set_key_enc_only(&ctx, (uint8_t *) i_pKey, AES_MAXKEYBITS);

    rijndael_encrypt(&ctx, acPlainText, (uint8_t *) acCypherText);
#endif
    
#ifdef KAT_DEBUG
    ConvertBinaryToUTF8HexString(sComputedCypherText,
            acCypherText,
            strlen(i_sPlainText) / 2);
    printf("PlainText=%s\n", i_sPlainText);
    printf("CypherText=%s\n", sComputedCypherText);
#endif

    if (memcmp(acCypherText, acKnownCypherText, strlen(i_sKnownCypherText) / 2) != 0)
    {
#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
	free(ks);
#endif
        return -1;
    }

#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
	aes_init_keysched(i_pKey, AES_MAXKEYBITS, ks);
	(void) aes_decrypt_block(ks, acCypherText, acDecryptedCypherText);
	free(ks);
#else
    rijndael_set_key(&ctx, (uint8_t *) i_pKey, AES_MAXKEYBITS);
    rijndael_decrypt(&ctx, (uint8_t *) acCypherText, acDecryptedCypherText);
#endif

    if (memcmp(acPlainText, acDecryptedCypherText, strlen(i_sPlainText) / 2) != 0)
    {
        return -1;
    }

    return 0;

}

static int KnownAnswerTestAESECB_GFSbox (void)
{
    /* 
     *  Test Vectors from AES Algorithm Validation Suite(AESAVS)
     */
    unsigned char acKey[AES_MAXKEYBYTES];
    memset(acKey, 0, sizeof (acKey));

    /*  
        # CAVS 6.1
        # Config info for Sun 1820 AES
        # AESVS GFSbox test data for ECB
        # State : Encrypt and Decrypt
        # Key Length : 256
        # Generated on Wed Aug 13 13:39:06 2008
     */
    const size_t GFSboxCount = 5;
    static char sPlainText[GFSboxCount][33];
    static char sKnownCypherText[GFSboxCount][33];
    strcpy(sPlainText[0], "014730f80ac625fe84f026c60bfd547d");
    strcpy(sPlainText[1], "0b24af36193ce4665f2825d7b4749c98");
    strcpy(sPlainText[2], "761c1fe41a18acf20d241650611d90f1");
    strcpy(sPlainText[3], "8a560769d605868ad80d819bdba03771");
    strcpy(sPlainText[4], "91fbef2d15a97816060bee1feaa49afe");
    
    strcpy(sKnownCypherText[0], "5c9d844ed46f9885085e5d6a4f94c7d7");
    strcpy(sKnownCypherText[1], "a9ff75bd7cf6613d3731c77c3b6d0c04");
    strcpy(sKnownCypherText[2], "623a52fcea5d443e48d9181ab32c7421" );
    strcpy(sKnownCypherText[3], "38f2c7ae10612415d27ca190d27da8b4" ); 
    strcpy(sKnownCypherText[4], "1bc704f1bce135ceb810341b216d7abe" );         

    
    for (size_t i = 0; i < GFSboxCount; i++)
    {
        if (AES_ECB_TestExecution(sPlainText[i], sKnownCypherText[i], acKey) != 0)
        {
#ifdef KAT_DEBUG
            printf("GFSbox[%d]: failed\n", i);
#endif
            return -1;
        }
#ifdef KAT_DEBUG
        printf("GFSbox[%d]: passed\n", i);
#endif
    }
    return 0;
}

static int KnownAnswerTestAESECB_KeySbox (void)
{
    unsigned char acKey[AES_MAXKEYBYTES];
    memset(acKey, 0, sizeof (acKey));

    /* 
        # CAVS 6.1
        # Config info for Sun 1820 AES
        # AESVS KeySbox test data for ECB
        # State : Encrypt and Decrypt
        # Key Length : 256
        # Generated on Wed Aug 13 13:39:07 2008
     */
    const size_t KeySboxCount = 16;
    static char sKey[KeySboxCount][65];
    static char sKnownCypherText[KeySboxCount][33];
    static char sPlainText[] = "00000000000000000000000000000000";

    strcpy(sKey[0], "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
    strcpy(sKey[1], "28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64");
    strcpy(sKey[2], "c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c");
    strcpy(sKey[3], "984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627");
    strcpy(sKey[4], "b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f");
    strcpy(sKey[5], "1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9");
    strcpy(sKey[6], "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf");
    strcpy(sKey[7], "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9");
    strcpy(sKey[8], "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e");
    strcpy(sKey[9], "6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707");
    strcpy(sKey[10], "ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc");
    strcpy(sKey[11], "13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887");
    strcpy(sKey[12], "07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee");
    strcpy(sKey[13], "90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1");
    strcpy(sKey[14], "b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07");
    strcpy(sKey[15], "fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e");
    strcpy(sKnownCypherText[0], "46f2fb342d6f0ab477476fc501242c5f");
    strcpy(sKnownCypherText[1], "4bf3b0a69aeb6657794f2901b1440ad4");
    strcpy(sKnownCypherText[2], "352065272169abf9856843927d0674fd");
    strcpy(sKnownCypherText[3], "4307456a9e67813b452e15fa8fffe398");
    strcpy(sKnownCypherText[4], "4663446607354989477a5c6f0f007ef4");
    strcpy(sKnownCypherText[5], "531c2c38344578b84d50b3c917bbb6e1");
    strcpy(sKnownCypherText[6], "fc6aec906323480005c58e7e1ab004ad");
    strcpy(sKnownCypherText[7], "a3944b95ca0b52043584ef02151926a8");
    strcpy(sKnownCypherText[8], "a74289fe73a4c123ca189ea1e1b49ad5");
    strcpy(sKnownCypherText[9], "b91d4ea4488644b56cf0812fa7fcf5fc");
    strcpy(sKnownCypherText[10], "304f81ab61a80c2e743b94d5002a126b");
    strcpy(sKnownCypherText[11], "649a71545378c783e368c9ade7114f6c");
    strcpy(sKnownCypherText[12], "47cb030da2ab051dfc6c4bf6910d12bb");
    strcpy(sKnownCypherText[13], "798c7c005dee432b2c8ea5dfa381ecc3");
    strcpy(sKnownCypherText[14], "637c31dc2591a07636f646b72daabbe7");
    strcpy(sKnownCypherText[15], "179a49c712154bbffbe6e7a84a18e220");
    
    for (size_t i = 0; i < KeySboxCount; i++)
    {
#ifdef KAT_DEBUG
        printf("KeySbox[%d]: \n", i);
#endif
        unsigned char acKey[256];
        if ((size_t) ConvertUTF8HexStringToBinary(
            sKey[i],
            acKey) != strlen(sKey[i]) / 2)
        {
#ifdef KAT_DEBUG
            printf("KeySbox[%d]: failed hex to binary conversion\n", i);
#endif
            return -1;
        }
        if (AES_ECB_TestExecution(sPlainText, sKnownCypherText[i], acKey) != 0)
        {
#ifdef KAT_DEBUG
            printf("KeySbox[%d]: failed test\n", i);
#endif
            return -1;
        }
#ifdef KAT_DEBUG
        printf("KeySbox[%d]: passed\n", i);
#endif
    }
    return 0;
}

int KnownAnswerTestHMACSHA1 (void)
{
    /* Test Data from RFC2202 */
    const static char sKey[] = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    unsigned char acKey[HMAC_LENGTH];
    const static char sPlainText[] = "Hi There";
    const static char sCypherText[] = "b617318655057264e28bc0b6fb378c8ef146be00";
    const unsigned char* aBuffersToHMAC[1];
    int aBuffersToHMACSize[1];
    unsigned char acCypherText[HMAC_LENGTH];
    unsigned char acComputedCypherText[HMAC_LENGTH];
    if ((size_t) ConvertUTF8HexStringToBinary(
        sKey,
        acKey) != sizeof (acKey))
    {
#ifdef KAT_DEBUG
        printf("HMAC-SHA1: failed hex to binary conversion for Key\n");
#endif
        return -1;
    }
    if ((size_t) ConvertUTF8HexStringToBinary(
        sCypherText,
        acCypherText) != sizeof (acCypherText))
    {
#ifdef KAT_DEBUG
        printf("HMAC-SHA1: failed hex to binary conversion for CypherText\n");
#endif
        return -1;
    }

    aBuffersToHMAC[0] = (unsigned char *) sPlainText;
    aBuffersToHMACSize[0] = strlen(sPlainText);

    if (!HMACBuffers(
        1,
        aBuffersToHMAC,
        aBuffersToHMACSize,
        acKey,
        sizeof (acKey),
        acComputedCypherText))
    {
#ifdef KAT_DEBUG
        printf("HMAC-SHA1: failed in HMACBuffers\n");
#endif
        return -1;
    }
    if (memcmp(acCypherText, acComputedCypherText, sizeof (acCypherText)) != 0)
    {
#ifdef KAT_DEBUG
        printf("HMAC-SHA1: failed comparison with expected cycphertext\n");
#endif
        return -1;
    }

    return 0;
}


int KnownAnswerTestAESECB (void)
{
    if (KnownAnswerTestAESECB_GFSbox() != 0)
    {
#ifdef KAT_DEBUG
        printf("GFSbox: test suite failed\n");
#endif
        return -1;
    }

    if (KnownAnswerTestAESECB_KeySbox() != 0)
    {
#ifdef KAT_DEBUG
        printf("KeySbox: test suite failed\n");
#endif
        return -1;
    }

    return 0;
}

#ifdef STAND_ALONE_TEST

int main ()
{
    // Known Answer Test on AES Key Wrap code
    if (KnownAnswerTestAESKeyWrap() != 0)
    {
        return -1;
    }

    if (KnownAnswerTestAESECB() != 0)
    {
        return -1;
    }

    if (KnownAnswerTestHMACSHA1() != 0)
    {
        return -1;
    }

    return 0;
}
#endif


