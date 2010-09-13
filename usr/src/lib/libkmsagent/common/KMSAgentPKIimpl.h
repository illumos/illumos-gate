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
 * \file KMSAgentPKIimpl.h
 */

#ifndef K_KMSAgentPKIimpl_h
#define K_KMSAgentPKIimpl_h

/**
 *   initializes the implementation environment for an X509
 *   certificate implementation and returns an opague handle to any
 *   resources that should be freed when use of the X.509
 *   implementation is complete.  This handle is used on all
 *   subsequent calls that may need to access this resource.
 */
void * InitializeCertImpl();

/**
 *  Save the X.509 Certificate in PEM format to the specified filename
 */
bool SaveX509CertTofile( 
                        void* const i_pImplResource,
                        const char * const i_pcFileName );

/**
 *  Save the X.509Certificate in PEM format to the specified buffer
 *  and set the length of the certificate in the location referenced
 *  by o_pActualLength
 */
bool SaveX509CertToBuffer(
                        void* const             i_pImplResource,
                        unsigned char * const   i_pcBuffer,
                        int                     i_iBufferLength,
                        int * const             o_pActualLength );

/**
 *  loads the X.509 certificate from i_pcFileName and keeps a reference to it
 *  via i_pImplResource
 */
bool LoadX509CertFromFile( 
                            void* const i_pImplResource,
                            const char * const i_pcFileName );

/**
 *  load the X.509 certificate from i_pX509Buffer and keeps a reference to it
 *  via i_pImplResource
 */
bool LoadX509CertFromBuffer( 
                           void* const i_pImplResource,
                           void* const i_pX509Cert,
                           int         i_iLength);
                                                    
/**
 *   frees any resources allocated by <code>InitializeCertImpl</code>
 */ 
void FinalizeCertImpl(
                        void* i_pImplResource);

/**
 *  print the X.509 certificate to stdout
 */
bool PrintX509Cert( void* const i_pImplResource );

/**
 *   initializes the implementation environment for a public or private key
 *   and returns an opague handle to any resources that should be freed
 *   when use of the key is complete.  This handle is used
 *   on all subsequent calls that may need to access this resource.
 */
void * InitializePKeyImpl();

/**
 *   frees any resources allocated by <code>InitializePKeyImpl</code>
 */ 
void FinalizePKeyImpl( void * i_pPKeyImpl );

#ifdef KMSUSERPKCS12
void *GetPKey( void *i_pImplResource);
void SetPKey( void *i_pImplResource, void *i_pPKey);
void *GetCert( void *i_pImplResource);
void SetCert( void *i_pImplResource, void *cert);
#endif

/**
 *   Stores the private key in a memory buffer referenced by
 *   i_pcBuffer with the length of the key being stored in the area
 *   referenced by o_pActualLength.
 *
 */
bool SavePrivateKeyToBuffer(
                        void * const          i_pPKeyImpl,
                        unsigned char * const i_pcBuffer, 
                        int                   i_iBufferLength, 
                        int * const           o_pActualLength,
			            const char * const    i_pPassphrase, 
                        int                   i_iFormat);

/**
 *   load the private key into this object from the specified buffer
 */
bool LoadPrivateKeyFromBuffer(
                        void * const        i_pPKeyImpl,
                        unsigned char *     i_pcBuffer,
			            int                 i_iLength, 
                        const char * const  i_pPassphrase, 
                        int                 i_iFormat);

/**
 *   Stores the pubic key in a memory buffer referenced by
 *   i_pcBuffer with the length of the key being stored in the area
 *   referenced by o_pActualLength.
 *
 */
bool SavePublicKeyToBuffer(
                        void * const          i_pPKeyImpl,
                        unsigned char * const i_pcBuffer, 
                        int                   i_iBufferLength, 
                        int * const           o_pActualLength,
                        int                   i_iFormat);

/**
 *  load a public key into this object from the specified buffer
 */
bool LoadPublicKeyFromBuffer(
                        void * const        i_pPKeyImpl,
                        unsigned char *     i_pcBuffer,
			            int                 i_iLength, 
                        int                 i_iFormat);

/**
 *  encrypt the plaintext using RSA encryption with the RSA public
 *  key provided and return resulting cyphertext
 */
bool PublicKeyEncrypt (int i_iLength,
                       const unsigned char * const i_pcPlainText,
                       unsigned char * const o_pcCypherText,
                       int * const o_pActualLength,
                       void * i_pRSAPublicKey);

#endif // K_KMSAgentPKIimpl_h

