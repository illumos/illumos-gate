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
 *  \file KMSAgentPKICert.cpp
 *
 *  This is an implementation of PKICommon.h CCertificate class.
 */

#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <string.h>

#ifdef KMSUSERPKCS12
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#endif

#include "SYSCommon.h"
#include "KMSAgentPKICommon.h"
#include "KMSAgentPKIimpl.h"

/////////////////////////////////////////////////////////////////////////
// CCertificate
//
CCertificate::CCertificate()
{
   m_pCertImpl = InitializeCertImpl();
   
   FATAL_ASSERT( m_pCertImpl != NULL );
}


CCertificate::~CCertificate()
{
   if ( m_pCertImpl != NULL )
   {
      FinalizeCertImpl( m_pCertImpl );
   }
}

/**
 * Save - This OVERLOADED method saves the Cert into a file
 *  @param i_pcFileName      - filename of file to save into
 *  @param i_iFormat         - IGNORED
 * 
 *  @returns bool   - success (true = successful)
 */
bool CCertificate::Save( const char * const i_pcFileName, 
                         int i_iFormat )
{ 
   return SaveX509CertTofile( m_pCertImpl, i_pcFileName );
}

/**
 *  Save - This OVERLOADED method saves the Cert into a buffer
 *  @param i_pcBuffer       - buffer to save into
 *  @param i_BufferLength   - length of buffer to save
 *  @param o_pActualLength  - length of buffer saved
 *  @param i_iFormat         - IGNORED
 * 
 *  @returns bool   - success (true = successful)
 */
bool CCertificate::Save( unsigned char * const      i_pcBuffer, 
                         int                        i_iBufferLength,
                         int * const                o_pActualLength,
                         int                        i_iFormat )
{
   return SaveX509CertToBuffer( m_pCertImpl, 
                                i_pcBuffer, 
                                i_iBufferLength, 
                                o_pActualLength );
}

/**
 * Load
 * This OVERLOADED method loads the Cert from a FILE
 * @param i_pcFileName   - name of file to load from
 * @param i_iFormat      -  IGNORED
 * 
 * @returns bool   - success (true = successful)
 */

bool CCertificate::Load( const char * const i_pcFileName, 
                         int                i_iFormat )
{
   return LoadX509CertFromFile( m_pCertImpl, i_pcFileName );
}

/**
 * Load 
 * This OVERLOADED method loads the Cert from a buffer
 * @param i_pcBuffer   - buffer to load from 
 * @param i_iLength    - amount to load from buffer
 * @param i_iFormat    -  IGNORED
 * 
 * @returns bool   - success (true = successful)
 */
bool CCertificate::Load( unsigned char * const i_pcBuffer,
                         int                   i_iLength,
                         int                   i_iFormat )
{
   return LoadX509CertFromBuffer( m_pCertImpl, i_pcBuffer, i_iLength );
}

/** 
 * Dump
 * dump the readable format to standard output
 * @returns bool   - success (true = successful)
 */
bool CCertificate::Dump()
{
   return PrintX509Cert( m_pCertImpl );
}

#ifdef KMSUSERPKCS12
bool
CCertificate::LoadPKCS12CertAndKey(
	char *filename,
	int i_iFormat,
        CPrivateKey *i_pPrivateKey,
	char *i_pPassphrase)
{
	BIO *pFileBio= NULL;
	X509 *pRequest =NULL;

	pFileBio = BIO_new(BIO_s_file());
	if (pFileBio == NULL)
		return false;
	if (!BIO_read_filename(pFileBio, filename)) {
		BIO_free(pFileBio);
		return (false);
	}

	switch( i_iFormat ) {
		case FILE_FORMAT_DER:

		pRequest=d2i_X509_bio(pFileBio, NULL);
		if (pRequest == NULL) {
			// fixme: log: invalid certificate format
			return false;
		}
		break;

		case FILE_FORMAT_PEM:

		pRequest=PEM_read_bio_X509(pFileBio, NULL, NULL, NULL);
		if (pRequest == NULL) {
			// fixme: log: invalid certificate format
			return false;
		}
		break;

		case FILE_FORMAT_PKCS12:
		PKCS12* pPKCS12Request = d2i_PKCS12_bio(pFileBio, NULL);
		if (pPKCS12Request == NULL) {
			// fixme: log: invalid certificate format
			return false;
		}

		// convert PKCS12 to X509
		EVP_PKEY *pKeyTemp = NULL;
		if (!PKCS12_parse(pPKCS12Request, i_pPassphrase,
		    &pKeyTemp, &pRequest, NULL)) {
			// fixme: log: invalid certificate format or passphrase
			PKCS12_free(pPKCS12Request);
			return false;
		}

		if (pKeyTemp && i_pPrivateKey) {
			i_pPrivateKey->SetNative((void *)pKeyTemp);
		} else if (pKeyTemp)
			EVP_PKEY_free(pKeyTemp);

		PKCS12_free(pPKCS12Request);
		break;
	}
	if (pRequest != NULL) {
		SetCert(m_pCertImpl, (void *)pRequest);
	}

	return (true);
}

void *
CCertificate::SaveCertToPKCS12MemoryBIO(
	CPrivateKey* i_pPrivateKey,
	char *i_sPassphrase)
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

    PKCS12 *p12 = PKCS12_create(i_sPassphrase,
                    NULL,
                    (EVP_PKEY *)i_pPrivateKey->GetNative(),
                    (X509 *)GetCert(m_pCertImpl),
                    NULL,
                    0,
                    0,
                    0,
                    0,
                    0);
    if ( ! p12 )
    {
        return NULL;
    }

    // now pMemBIO != NULL, remember to free it before exiting
    iReturn = i2d_PKCS12_bio(pMemBio, p12);

    if(!iReturn) // return 0: means error occurs
    {
        //fixme: log -- could not export private key
        BIO_free(pMemBio);
        return NULL;
    }

    return (void *)pMemBio;
}

bool
CCertificate::SavePKCS12(
	unsigned char *i_pcBuffer,
	int i_iBufferLength,
	int *o_pActualLength,
	CPrivateKey* i_pPrivateKey,
	char* i_sPassphrase )
{
    BIO *pMemBio = NULL;
    char *pData = NULL;
    int iLength;

    // sanity check
    if(i_pcBuffer == NULL) return false;
    if(i_iBufferLength <= 0) return false;
    if(o_pActualLength == NULL) return false;

    // create memory BIO
    pMemBio = (BIO *)SaveCertToPKCS12MemoryBIO(i_pPrivateKey, i_sPassphrase);

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
#endif /* PKCS12 */
