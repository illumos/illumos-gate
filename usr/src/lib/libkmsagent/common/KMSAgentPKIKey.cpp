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
 * \file KMSAgentPKIKey.cpp
 */
#include <stdio.h>

#include "SYSCommon.h"
#include "KMSAgentPKICommon.h"
#include "KMSAgentPKIimpl.h"

///////////////////////////////////////////////////////////////////////////////////////
// public key methods
///////////////////////////////////////////////////////////////////////////////////////
CPublicKey::CPublicKey()
{
   m_pPublicKeyImpl = InitializePKeyImpl();
   
   FATAL_ASSERT( m_pPublicKeyImpl != NULL );
   
}

/**
 * This method saves public key into a buffer,
 * it also returns the actual used buffer length.
 * @param i_pcBuffer Buffer to receive public key
 * @param i_iBufferLength length of the buffer provided
 * @param o_pActualLength actual length of the public key stored into the buffer
 * @param i_iFormat key format, @see EnumPKIFileFormat
 */
bool CPublicKey::Save(  unsigned char * const      i_pcBuffer, 
                        int                        i_iBufferLength,
                        int * const                o_pActualLength,
                        int                        i_iFormat )
{
   return SavePublicKeyToBuffer( m_pPublicKeyImpl, 
                                 i_pcBuffer, 
                                 i_iBufferLength, 
                                 o_pActualLength, 
                                 i_iFormat );
}

bool CPublicKey::Load(unsigned char * const i_pcBuffer,
                       int                   i_iLength,
                       int                   i_iFormat)
{ 
   return LoadPublicKeyFromBuffer( m_pPublicKeyImpl, 
                                    i_pcBuffer, 
                                    i_iLength, 
                                    i_iFormat );
}

bool CPublicKey::Encrypt (int i_iLength,
                  const unsigned char * const i_pcPlainText,
                  unsigned char * const o_pcCypherText,
                  int * const o_pActualLength)
{
    return PublicKeyEncrypt(i_iLength,i_pcPlainText,o_pcCypherText,o_pActualLength, m_pPublicKeyImpl );
}

CPublicKey::~CPublicKey()
{
   if(m_pPublicKeyImpl != NULL)
   {
      FinalizePKeyImpl( m_pPublicKeyImpl );
   }
}

///////////////////////////////////////////////////////////////////////////////////////
// private key methods
///////////////////////////////////////////////////////////////////////////////////////

CPrivateKey::CPrivateKey()
{
   m_pPKeyImpl = InitializePKeyImpl();
   
   FATAL_ASSERT( m_pPKeyImpl != NULL );
   
}

/**
 * This method saves private key into a buffer,
 * it also returns the actual used buffer length.
 */
bool CPrivateKey::Save( unsigned char * const      i_pcBuffer, 
                        int                        i_iBufferLength,
                        int * const                o_pActualLength,
                        const char * const         i_pPassphrase, 
                        int                        i_iFormat )
{
   return SavePrivateKeyToBuffer(m_pPKeyImpl, 
                                 i_pcBuffer, 
                                 i_iBufferLength, 
                                 o_pActualLength, 
                                 i_pPassphrase, 
                                 i_iFormat );
}

bool CPrivateKey::Load(unsigned char * const i_pcBuffer,
                       int                   i_iLength,
                       const char * const    i_pPassphrase,
                       int                   i_iFormat)
{ 
   return LoadPrivateKeyFromBuffer( m_pPKeyImpl, 
                                    i_pcBuffer, 
                                    i_iLength, 
                                    i_pPassphrase, 
                                    i_iFormat );
}

CPrivateKey::~CPrivateKey()
{
   if(m_pPKeyImpl != NULL)
   {
      FinalizePKeyImpl( m_pPKeyImpl );
   }
}
#ifdef KMSUSERPKCS12
void
*CPrivateKey::GetNative()
{
	return GetPKey(m_pPKeyImpl);
}
void
CPrivateKey::SetNative(void *pKey)
{
	SetPKey(m_pPKeyImpl, pKey);
	return;
}
#endif
