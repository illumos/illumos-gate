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
 * \file KMSAgentPKICertOpenSSL.cpp
 */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "SYSCommon.h"
#include "KMSAgentPKIimpl.h"

typedef struct X509control
{
    X509*   pX509;
} X509control;

void * InitializeCertImpl()
{
    X509control *pX509Control = (X509control *) malloc(sizeof(X509control));

    if ( pX509Control != NULL )
    {
        pX509Control->pX509 = NULL;
    }

    return pX509Control;
}

/**
 * export the Cert to a memory BIO, if error, return NULL
 */
BIO* SaveCertToMemoryBIO( X509control* i_pX509control )
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

    //iReturn = PEM_write_bio_X509(pMemBio, m_pNative);
    iReturn = PEM_write_bio_X509(pMemBio, i_pX509control->pX509);

    if(!iReturn) // return 0: means error occurs
    {
        //fixme: log -- could not export private key
        BIO_free(pMemBio);
        return NULL;
    }

    return pMemBio;
}

bool SaveX509CertTofile( 
                        void* const i_pImplResource,
                        const char * const i_pcFileName )
{
    FATAL_ASSERT( i_pImplResource != NULL && i_pcFileName );

    X509control* pX509control = (X509control*)i_pImplResource;
    // the BIO for output, need cleanup when exiting
    BIO *pMemBio = NULL;
    int iLength;
    unsigned char *pData;
    FILE *fp;

    // create memory BIO
    pMemBio = SaveCertToMemoryBIO( pX509control );

    if(pMemBio == NULL)
    {
        return false;
    }

    // now pMemBIO != NULL, remember to free it before exiting
    iLength = BIO_get_mem_data(pMemBio, &pData);

    // open the file
    fp = fopen(i_pcFileName, "wb");
    if(fp == NULL)
    {
        //fixme: log -- could not open file for exporting Cert
        BIO_free(pMemBio);
        return false;
    }

    fwrite(pData, 1, iLength, fp);
    fclose(fp);

    BIO_free(pMemBio); // BIO_free close the file and clean the BIO
    return true;
}

bool SaveX509CertToBuffer(
                        void* const             i_pImplResource,
                        unsigned char * const   i_pcBuffer,
                        int                     i_iBufferLength,
                        int * const             o_pActualLength )
{
    FATAL_ASSERT( i_pImplResource != NULL && 
                  i_pcBuffer && 
                  o_pActualLength &&
                  i_iBufferLength > 0 );

    X509control* pX509control = (X509control*)i_pImplResource;

    BIO *pMemBio = NULL;
    char *pData = NULL;
    int iLength;

    // create memory BIO
    pMemBio = SaveCertToMemoryBIO( pX509control );

    if( pMemBio == NULL )
    {
        //fixme: log -- no memory
        return false;
    }

    iLength = BIO_get_mem_data( pMemBio, &pData );

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
 * import the Cert from a BIO, if error, return NULL
 */
bool LoadCertFromBIO(X509control* i_pX509control, BIO *i_pBio)
{
    X509 *pRequest = NULL;

    if (i_pX509control == NULL) return false;

    if(i_pBio == NULL) return false;

    //if(m_pNative != NULL) return false; // do not allow overwrite
    if (i_pX509control->pX509 != NULL ) return false;

    pRequest=PEM_read_bio_X509(i_pBio, NULL, NULL, NULL);

    if (pRequest == NULL)
    {
        // fixme: log: invalid certificate format
        return false;
    }
    //m_pNative = pRequest;
    i_pX509control->pX509 = pRequest;

    return true;
}

bool LoadX509CertFromFile( 
                            void* const i_pImplResource,
                            const char * const i_pcFileName )

{
    X509control* pX509control = (X509control*) i_pImplResource;
    if (pX509control == NULL) 
    {
        return false;
    }

    BIO *pFileBio=NULL;
    bool bReturn;

    pFileBio=BIO_new(BIO_s_file());
    if (pFileBio == NULL)
    {
        //fixme: log -- no memory
        return false;
    }

    if (!BIO_read_filename(pFileBio,i_pcFileName))
    {
        //fixme log -- could not open file
        BIO_free(pFileBio);
        return false;
    }

    bReturn = LoadCertFromBIO(pX509control, pFileBio);

    BIO_free(pFileBio);

    return bReturn;
}


bool LoadX509CertFromBuffer(
                           void* const i_pImplResource,
                           void* const i_pX509Cert,
                           int         i_iLength)
 {
    X509control* pX509control = (X509control*)i_pImplResource;

    if(pX509control == NULL)
    {
        return false;
    }

    BIO *pMemBio;
    bool bReturn;
    // create a mem bio from the given buffer
    // Note that BIO_new_mem_buf() creates a BIO which never destroy the memory
    //    attached to it.
    pMemBio = BIO_new_mem_buf(i_pX509Cert, i_iLength);
    if (pMemBio == NULL)
    {
        //fixme: log -- no memory
        return false;
    }
    bReturn = LoadCertFromBIO(pX509control, pMemBio);

    BIO_free(pMemBio);

    return bReturn;
}

void FinalizeCertImpl( void* i_pImplResource )
{
    if ( i_pImplResource != NULL )
    {
        free(i_pImplResource);
    }
}

bool PrintX509Cert( void* const i_pImplResource )
{
    BIO *pMemBio;
    char *pData;
    int iLength,i;
    X509control* pX509control = (X509control*)i_pImplResource;
    pMemBio = BIO_new(BIO_s_mem());
    if(pMemBio == NULL)
    {
        return false;
    }

    //X509_print(pMemBio,m_pNative);
    X509_print(pMemBio, pX509control->pX509);

    iLength = BIO_get_mem_data(pMemBio, &pData);

    for(i = 0; i < iLength; i++)
    {
        printf("%c", pData[i]);
    }

    BIO_free(pMemBio);

    return true;

}
#ifdef K_SOLARIS_PLATFORM
void *GetCert(void* i_pImplResource )
{
	X509control* pX509control = (X509control*)i_pImplResource;
	return ((void *)pX509control->pX509);
}

void SetCert(void* i_pImplResource, void *cert)
{
	X509control* pX509control = (X509control*)i_pImplResource;
	pX509control->pX509 = (X509 *)cert;
	return;
}
#endif
