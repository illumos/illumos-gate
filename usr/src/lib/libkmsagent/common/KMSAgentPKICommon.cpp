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
 * \file KMSAgentPKICommon.cpp
 */
#include <stdio.h>

#include "SYSCommon.h"
#include "KMSAgentPKICommon.h"
#include "KMSAgentStringUtilities.h"

#include "KMSAgent_direct.h"


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPKI::CPKI()
{
   m_iKeyLength = DEFAULT_KEY_SIZE;
   
   // used for CA
   m_pCACertificate = NULL;
   m_pCAPrivateKey = NULL;
}

// BEN - make these
// global lengths
int iLength1 = 0;
int iLength2 = 0;

// THIS CAN'T BE STACK DATA - TOO BIG
static unsigned char aTempBuffer[MAX_CERT_SIZE + MAX_KEY_SIZE];
#ifdef METAWARE
static char aNotherTempBuffer[50];
#endif

// used by StoreAgentPKI - KMSAgentStorage.cpp

bool CPKI::ExportCertAndKeyToFile(
   CCertificate* const         i_pCertificate,  
   CPrivateKey*  const         i_pPrivateKey,
   const char* const           i_pcFileName,
   const char* const           i_sPassphrase,
   EnumPKIFileFormat           i_eFileFormat )
{
   FATAL_ASSERT( i_pCertificate && i_pPrivateKey && i_pcFileName );
   
   
   memset( aTempBuffer, 0, MAX_CERT_SIZE + MAX_KEY_SIZE );

#ifdef KMSUSERPKCS12
    if ( i_eFileFormat == FILE_FORMAT_PKCS12 )
    {
        if ( !i_pCertificate->SavePKCS12(aTempBuffer,
                                MAX_CERT_SIZE,
                                &iLength1,
                                i_pPrivateKey,
                                (char*)i_sPassphrase ) )
        {
            return false;
        }
    } else {
#endif
   
   // Overloaded Save method implemented in KMSAgentPKICert.cpp
   // this method saves Certificate to the temporary buffer, not a file
   // but a side effect is to get the actual file length
   if ( !i_pCertificate->Save(aTempBuffer, 
                              MAX_CERT_SIZE, 
                              &iLength1,          /* returned - actual length
                                                     written */
                              i_eFileFormat) )
   {
      return false;
   }
   
   // Overloaded Save method implemented in KMSAgentPKIKey.cpp
   // this method saves keys to the temporary buffer, not a file,
   // but a side effect is to get the actual file length
   if ( !i_pPrivateKey->Save(aTempBuffer + iLength1, 
                             MAX_KEY_SIZE, 
                             &iLength2,          /* returned - actual length
                                                    written */
                             i_sPassphrase, 
                             i_eFileFormat) )
   {
      return false;
   }
   
#ifdef KMSUSERPKCS12
	}
#endif

   // now write the temporary buffer to a file
   myFILE* pFile = fopen( i_pcFileName, "wb" );
   if ( pFile == NULL )
   {
      return false;
   }

#ifdef KMSUSERPKCS12
#ifdef K_SOLARIS_PLATFORM
	int fd = fileno(pFile);

	/* Make sure this file is read/write for the OWNER only! */
	(void) fchmod(fd, 0600);
#endif
#endif

#ifdef METAWARE
   // write out the two file lengths
   snprintf(aNotherTempBuffer, sizeof(aNotherTempBuffer), "iLength1=%x\n", iLength1);
   fputs((const char*)aNotherTempBuffer, pFile);
   
   snprintf(aNotherTempBuffer, sizeof(aNotherTempBuffer), "iLength2=%x\n", iLength2);
   fputs((const char*)aNotherTempBuffer, pFile);
#endif

   int iBytesWritten = fwrite( (const char*)aTempBuffer,  // from
                               1,                         // size
                               iLength1+iLength2,         // actual file length
                               pFile );                   // to-file
   
   fclose( pFile );
   
   return ( iBytesWritten == (iLength1+iLength2) );
}


CPKI::~CPKI()
{
   // empty
}

