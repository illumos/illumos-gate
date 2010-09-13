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
 * \file KMSAgentPKIKeyOpenSSL.cpp
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "SYSCommon.h"
#include "KMSAgentPKIimpl.h"

typedef struct PKeyControl
{
    EVP_PKEY*   pPKey;
} PKeyControl;

void * InitializePKeyImpl()
{
    PKeyControl *pPKeyControl = 
       (PKeyControl *) malloc(sizeof(PKeyControl));

    if ( pPKeyControl != NULL )
    {
        pPKeyControl->pPKey = NULL;
    }

    return pPKeyControl;
}

void FinalizePKeyImpl( void * i_pPKeyImpl )
{
    if ( i_pPKeyImpl != NULL )
    {
        free(i_pPKeyImpl);
    }
}

#ifdef KMSUSERPKCS12
void *GetPKey(void *i_pPKeyImpl) {
	PKeyControl* pPKeyControl = (PKeyControl*) i_pPKeyImpl;
	return ((void *)pPKeyControl->pPKey);
}

void SetPKey(void *i_pPKeyImpl, void *pKey) {
	PKeyControl* pPKeyControl = (PKeyControl*) i_pPKeyImpl;
	pPKeyControl->pPKey = (EVP_PKEY *)pKey;
	return;
}
#endif

/**
 * export the private key to a memory BIO, if error, return NULL
 */
BIO* SavePrivateKeyToMemoryBIO(PKeyControl* const i_pPKeyControl,
                               const char * const i_pPassphrase)
{
   BIO *pMemBio = NULL;
   const EVP_CIPHER *pCipher = NULL;
   int iReturn;

   // set cipher, if passphrase is not empty
   if(i_pPassphrase != NULL)
   {
      pCipher= EVP_des_ede3_cbc(); //NULL means no password protection
   }

   // create memory BIO
   pMemBio = BIO_new(BIO_s_mem());

   if(pMemBio == NULL)
   {
      //fixme: log -- no memory
      return NULL;
   }

  iReturn = PEM_write_bio_PrivateKey
     (pMemBio, 
      i_pPKeyControl->pPKey,
      pCipher, 
      NULL,0,NULL, (char*) i_pPassphrase);

   if(!iReturn) // return 0: means error occurs
   {
      //fixme: log -- could not export private key
      BIO_free(pMemBio);
      return NULL;
   }

   return pMemBio;
}

bool SavePrivateKeyToBuffer(
   void * const          i_pPKeyImpl,
   unsigned char * const i_pcBuffer, 
   int                   i_iBufferLength, 
   int * const           o_pActualLength,
   const char * const    i_pPassphrase, 
   int                   i_iFormat)
{
    PKeyControl* pPKeyControl = (PKeyControl*) i_pPKeyImpl;

    FATAL_ASSERT( pPKeyControl && 
        i_pcBuffer && 
        i_iBufferLength > 0 && 
        o_pActualLength );

    BIO *pMemBio = NULL;
	char *pData = NULL;
	int iLength;

	// create memory BIO
	pMemBio = SavePrivateKeyToMemoryBIO( pPKeyControl, i_pPassphrase );

	if(pMemBio == NULL)
	{
		//fixme: log -- no memory
		return false;
	}

	iLength = BIO_get_mem_data(pMemBio, &pData);

    // If the output buffer is a string, it needs to be NULL terminated
    // So always append a NULL to the output
    if(iLength + 1 > i_iBufferLength)
	{
		//fixme: log -- buffer too small
		BIO_free(pMemBio);
		return false;
	}
	// copy the data to given buffer
	memcpy(i_pcBuffer, pData, iLength);
    // NULL terminate the string
    i_pcBuffer[iLength] = '\0';
	*o_pActualLength = iLength;

	// free memory
	BIO_free(pMemBio);

	return true;
}

/**
 * import the private key from a BIO, if error, return NULL
 */
bool LoadPrivateKeyFromBIO(PKeyControl* const io_pPKeyControl,
                           BIO *i_pBio, 
                           char *i_pPassphrase ) 
{
    if (io_pPKeyControl == NULL)
    {
        return false;
    }
    
    EVP_PKEY *pKey = NULL;

	if(i_pBio == NULL) 
    {
        return false;
    }

    if ( io_pPKeyControl != NULL && io_pPKeyControl->pPKey != NULL )
    {
        return false; // do not allow overwrite
    }

	pKey=PEM_read_bio_PrivateKey(i_pBio,NULL,NULL,i_pPassphrase);
	if (pKey == NULL)
	{
		// fixme: log: invalid private key format or passphrase
		return false;
	}

    io_pPKeyControl->pPKey = pKey;

	return true;
}

bool LoadPrivateKeyFromBuffer(
   void * const        i_pPKeyImpl,
   unsigned char *     i_pcBuffer,
   int                 i_iLength, 
   const char * const  i_pPassphrase, 
   int                 i_iFormat)
{ 
    PKeyControl* const pPKeyControl = (PKeyControl*) i_pPKeyImpl;

    FATAL_ASSERT( i_pPKeyImpl && i_pcBuffer );

    bool bReturn;
	BIO *pMemBio;
	// create a mem bio from the given buffer
	// Note that BIO_new_mem_buf() creates a BIO which never 
        // destroy the memory attached to it.
	pMemBio = BIO_new_mem_buf(i_pcBuffer, i_iLength);
	if (pMemBio == NULL)
	{
		//fixme: log -- no memory
		return false;
	}
	bReturn = LoadPrivateKeyFromBIO( pPKeyControl, 
                    pMemBio, (char *)i_pPassphrase );

	BIO_free(pMemBio);

	return bReturn;
}

/**
 * export the public key to a memory BIO, if error, return NULL
 */
BIO* SavePublicKeyToMemoryBIO(PKeyControl* const i_pPublicKeyControl )
{
   BIO *pMemBio = NULL;

   int iReturn;

   // create memory BIO
   pMemBio = BIO_new(BIO_s_mem());

   if(pMemBio == NULL)
   {
      //fixme: log -- no memory
      return NULL;
   }
   
   iReturn = PEM_write_bio_PUBKEY(pMemBio,       
                        i_pPublicKeyControl->pPKey );

   if(!iReturn) // return 0: means error occurs
   {
      //fixme: log -- could not export private key
      BIO_free(pMemBio);
      return NULL;
   }

   return pMemBio;
}

bool SavePublicKeyToBuffer(
   void * const          i_pPKeyImpl,
   unsigned char * const i_pcBuffer, 
   int                   i_iBufferLength, 
   int * const           o_pActualLength,
   int                   i_iFormat)
{
    PKeyControl* pPublicKeyControl = (PKeyControl*) i_pPKeyImpl;

    FATAL_ASSERT( pPublicKeyControl && 
        i_pcBuffer && 
        i_iBufferLength > 0 && 
        o_pActualLength );

    BIO *pMemBio = NULL;
	char *pData = NULL;
	int iLength;

	// create memory BIO
	pMemBio = SavePublicKeyToMemoryBIO( pPublicKeyControl );

	if(pMemBio == NULL)
	{
		return false;
	}

	iLength = BIO_get_mem_data(pMemBio, &pData);

    // If the output buffer is a string, it needs to be NULL terminated
    // So always append a NULL to the output
    if(iLength + 1 > i_iBufferLength)
	{
		BIO_free(pMemBio);
		return false;
	}
	// copy the data to given buffer
	memcpy(i_pcBuffer, pData, iLength);
    // NULL terminate the string
    i_pcBuffer[iLength] = '\0';
	*o_pActualLength = iLength;

	// free memory
	BIO_free(pMemBio);

	return true;
}

/**
 * import the public key from a BIO, if error, return NULL
 */
bool LoadPublicKeyFromBIO(PKeyControl* const io_pPublicKeyControl,
                           BIO *i_pBio ) 
{
	EVP_PKEY *pKey = NULL;

    if(io_pPublicKeyControl == NULL) 
    {
        return false;
    }
    
    if(i_pBio == NULL) 
    {
        return false;
    }

    if ( io_pPublicKeyControl != NULL && io_pPublicKeyControl->pPKey != NULL )
    {
        return false; // do not allow overwrite
    }

    pKey = PEM_read_bio_PUBKEY(i_pBio, NULL, NULL, NULL);
    if (pKey == NULL)
    {
        // fixme: log: invalid public key format or passphrase
        return false;
    }

    io_pPublicKeyControl->pPKey = pKey;

	return true;
}

bool LoadPublicKeyFromBuffer(
   void * const        i_pPublicKeyImpl,
   unsigned char *     i_pcBuffer,
   int                 i_iLength, 
   int                 i_iFormat)
{ 
    PKeyControl* const pPublicKeyControl = (PKeyControl*) i_pPublicKeyImpl;

    FATAL_ASSERT( i_pPublicKeyImpl && i_pcBuffer );

    bool bReturn;
	BIO *pMemBio;
	// create a mem bio from the given buffer
	// Note that BIO_new_mem_buf() creates a BIO which never 
        // destroy the memory attached to it.
	pMemBio = BIO_new_mem_buf(i_pcBuffer, i_iLength);
	if (pMemBio == NULL)
	{
		//fixme: log -- no memory
		return false;
	}
	bReturn = LoadPublicKeyFromBIO( pPublicKeyControl, 
                    pMemBio );

	BIO_free(pMemBio);

	return bReturn;
}

bool PublicKeyEncrypt (int i_iLength,
                       const unsigned char * const i_pcPlainText,
                       unsigned char * const o_pcCypherText,
                       int * const o_pActualLength,
                       void * pPKeyControl )
{
    FATAL_ASSERT( i_pcPlainText );
    FATAL_ASSERT( o_pcCypherText );
    FATAL_ASSERT( o_pActualLength );
    FATAL_ASSERT( pPKeyControl );
    
    PKeyControl *pKeyControl = (PKeyControl *)pPKeyControl;
    EVP_PKEY * pEVP_PKEY = pKeyControl->pPKey;
    RSA * pRSAPublicKey = pEVP_PKEY->pkey.rsa;

//#if defined(DEBUG)
//    RSA_print_fp(stdout, pRSAPublicKey, 0);
//    printf("PublicKeyEncrypt(): RSA_size()=%d, cyphertextLen=%d\n", 
//            RSA_size(pRSAPublicKey),
//            i_iLength);
//#endif
    
    *o_pActualLength = RSA_public_encrypt(i_iLength,
                                          i_pcPlainText, 
                                          o_pcCypherText, 
                                          pRSAPublicKey,
                                          RSA_PKCS1_PADDING);

    if ( *o_pActualLength < 0 )
    {
        return false;     
    }
    else
    {
        return true;
    }
}
