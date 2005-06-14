/*
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Cylink Corporation © 1998
 * 
 * This software is licensed by Cylink to the Internet Software Consortium to
 * promote implementation of royalty free public key cryptography within IETF
 * standards.  Cylink wishes to expressly thank the contributions of Dr.
 * Martin Hellman, Whitfield Diffie, Ralph Merkle and Stanford University for
 * their contributions to Internet Security.  In accordance with the terms of
 * this license, ISC is authorized to distribute and sublicense this software
 * for the practice of IETF standards.  
 *
 * The software includes BigNum, written by Colin Plumb and licensed by Philip
 * R. Zimmermann for royalty free use and distribution with Cylink's
 * software.  Use of BigNum as a stand alone product or component is
 * specifically prohibited.
 *
 * Disclaimer of All Warranties. THIS SOFTWARE IS BEING PROVIDED "AS IS",
 * WITHOUT ANY EXPRESSED OR IMPLIED WARRANTY OF ANY KIND WHATSOEVER. IN
 * PARTICULAR, WITHOUT LIMITATION ON THE GENERALITY OF THE FOREGOING, CYLINK
 * MAKES NO REPRESENTATION OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * Cylink or its representatives shall not be liable for tort, indirect,
 * special or consequential damages such as loss of profits or loss of
 * goodwill from the use or inability to use the software for any purpose or
 * for any reason whatsoever.
 *
 * EXPORT LAW: Export of the Foundations Suite may be subject to compliance
 * with the rules and regulations promulgated from time to time by the Bureau
 * of Export Administration, United States Department of Commerce, which
 * restrict the export and re-export of certain products and technical data.
 * If the export of the Foundations Suite is controlled under such rules and
 * regulations, then the Foundations Suite shall not be exported or
 * re-exported, directly or indirectly, (a) without all export or re-export
 * licenses and governmental approvals required by any applicable laws, or (b)
 * in violation of any applicable prohibition against the export or re-export
 * of any part of the Foundations Suite. All export licenses for software
 * containing the Foundations Suite are the sole responsibility of the licensee.
 */
 
/****************************************************************************
*  FILENAME:  rand.c   PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:     Cryptographic Toolkit Functions File
*                   Random Number Generation Files
*  PUBLIC FUNCTIONS:
*      int InitRand( u_int16_t SEED_bytes, uchar  *SEED,
*                                       uchar  *RVAL )
*      int GenRand( u_int16_t A_bytes, uchar  *A,
*                                   uchar  *RVAL )
*	int MyGenRand( u_int16_t A_bytes,
*                  ord    *A,
*                  ord    *RVAL )

*   Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  10 Oct 94   KPZ     Added Shamir Key Sharing functions
*  10 Oct 94   KPZ     Modified SHA functions for arbitrary message length
*  12 Oct 94   KPZ     Modified SHA functions (new standard)
*  14 Oct 94   GKL     Second version (big endian support)
*  26 Oct 94   GKL     (alignment for big endian support & ERR_ALLOC)
*
****************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/

#include "port_before.h"

/* system files */
#ifdef VXD
#include <vtoolsc.h>
#else
#include <stdlib.h>
#include <string.h>
#endif

/* program files */
#ifdef VXD
#include "tkvxd.h"
#endif
#include "cylink.h"
#include "ctk_endian.h"
#include "toolkit.h"
#include "cencrint.h"
#include "sha.h"

#include "port_after.h"
extern u_int16_t DataOrder;
/****************************************************************************
*  PUBLIC FUNCTIONS DEFINITIONS
****************************************************************************/

/****************************************************************************
*  NAME:    int InitRand( u_int16_t SEED_bytes,
*                         uchar  *SEED,
*                         uchar  *RVAL)
*
*  DESCRIPTION:  Initialize Random number Generator
*
*  INPUTS:
*      PARAMETERS:
*          u_int16_t SEED_bytes  Length of SEED
*          uchar *SEED        Pointer to SEED value
*
*  OUTPUT:
*      PARAMETERS:
*          uchar *RVAL        Pointer to RVAL
*
*      RETURN:
*          SUCCESS            No errors
*          ERR_INPUT_LEN      Invalid length for input data
*          ERR_DATA           Generic data error
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*
****************************************************************************/

int InitRand( u_int16_t SEED_bytes,
              uchar  *SEED,
        uchar  *RVAL )
{
    int  status = SUCCESS;          /* function return status */
    if ( SEED_bytes == 0 )
    {
            status = ERR_INPUT_LEN;
        return status;
    }
    if ( SEED_bytes < SHA_LENGTH )
    {
        status = ERR_DATA;
        return status;
    }
    memcpy( RVAL, SEED, SHA_LENGTH);
      return status;
}


/****************************************************************************
*  NAME:    int GenRand( u_int16_t A_bytes,
*                        uchar  *A,
*                        uchar  *RVAL)
*
*  DESCRIPTION:  Generate random number.
*
*  INPUTS:
*      PARAMETERS:
*          u_int16_t A_bytes       Length of A
*          uchar *A             Pointer to A value
*
*  OUTPUT:
*      PARAMETERS:
*          uchar *RVAL          Pointer to RVAL
*
*      RETURN:
*          SUCCESS              No errors
*          ERR_INPUT_LEN        Invalid length for input data
*          ERR_DATA             Generic data error
*          ERR_ALLOC            Insufficient memory
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*  26 Oct 94   GKL     (alignment for big endian support & ERR_ALLOC)
*
****************************************************************************/
int GenRand( u_int16_t A_bytes,
             uchar  *A,
             uchar  *RVAL )
{
   int  status = SUCCESS;          /* function return status */
    ord *RVAL_a;
    SHA_context hash_context;       /* SHA context structure */
	 uchar M[DSS_LENGTH_MIN];        /* message block */
    uchar hash_result[SHA_LENGTH];
    u_int16_t i;
    u_int16_t sha_block;              /* number of sha blocks */
    u_int16_t sha_rem;                /* size of last block */
    if ( A_bytes == 0 )
    {
     status = ERR_INPUT_LEN;
         return status;
    }
    sha_block = (u_int16_t) (A_bytes / SHA_LENGTH);   /* number of sha blocks */
    sha_rem = (u_int16_t) (A_bytes % SHA_LENGTH);     /* size of last block */
    if ( sha_rem == 0 )                 /* last block = SHA_LENGTH */
    {
        sha_block--;
    }
    for ( i = 0; i <= sha_block; i++)
    {
        SHAInit ( &hash_context );
        memcpy( M, RVAL, SHA_LENGTH);
        memset( M + SHA_LENGTH, 0, DSS_LENGTH_MIN - SHA_LENGTH );
        if ( (status = SHAUpdate( &hash_context, M, DSS_LENGTH_MIN ))
          != SUCCESS )
        {
           return status;                        /* error */
        }
        if ( (status=MySHAFinal (&hash_context, hash_result )) != SUCCESS )
        {
           return status;                       /* error */
        }
    
        BigSwap(RVAL, SHA_LENGTH);
        ALIGN_CALLOC_COPY(RVAL, RVAL_a, SHA_LENGTH);
        if ( status !=  SUCCESS )
        {
            ALIGN_COPY_FREE(RVAL_a,RVAL,SHA_LENGTH);
            BigSwap(RVAL, SHA_LENGTH);
            return status;     /* ERR_ALLOC   insufficient memory */
	    }
	    Sum_Q( RVAL_a, 1, SHA_LENGTH / sizeof(ord) );
	    Sum_big( RVAL_a,                 /* RVAL=RVAL+hash_result*/
				  (ord *)hash_result,
				 RVAL_a, SHA_LENGTH / sizeof(ord) );
        ALIGN_COPY_FREE(RVAL_a,RVAL,SHA_LENGTH);
        BigSwap(RVAL, SHA_LENGTH);
#ifdef CTK_BIG_ENDIAN
        ByteSwap(hash_result,SHA_LENGTH);
#endif
        BigSwap(hash_result, SHA_LENGTH);
        if ( i == sha_block  && sha_rem != 0 )  /* last block < SHA_LENGTH*/
        {
           memcpy( A + i * SHA_LENGTH, hash_result,
                sha_rem * sizeof (uchar));
        }
        else            /* last block = SHA_LENGTH*/
        {
           memcpy( A + i * SHA_LENGTH, hash_result,
               SHA_LENGTH * sizeof (uchar));
        }
    }
    return status;
}



/****************************************************************************
*  NAME:        int MyGenRand( u_int16_t A_bytes,
*                              ord    *A,
*                              ord    *RVAL)
*
*  DESCRIPTION:  Generate random number.
*
*  INPUTS:
*          PARAMETERS:
*                  u_int16_t A_bytes               Length of A
*              ord   *A             Pointer to A value
*
*  OUTPUT:
*          PARAMETERS:
*          ord   *RVAL          Pointer to RVAL
*
*          RETURN:
*                  SUCCESS              No errors
*          ERR_INPUT_LEN        Invalid length for input data
*                  ERR_DATA                         Generic data error
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ         Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/
int MyGenRand( u_int16_t A_bytes,
               ord    *A,
               ord    *RVAL )
{
   int  status = SUCCESS;          /* function return status */
    SHA_context hash_context;       /* SHA context structure */
	  uchar M[DSS_LENGTH_MIN];        /* message block */
    uchar hash_result[SHA_LENGTH];
	u_int16_t i;
    u_int16_t sha_block;              /* number of sha blocks */
    u_int16_t sha_rem;                /* size of last block */
    if ( A_bytes == 0 )
    {
         status = ERR_INPUT_LEN;
         return status;
    }
    sha_block = (u_int16_t) (A_bytes / SHA_LENGTH);   /* number of sha blocks */
    sha_rem = (u_int16_t) (A_bytes % SHA_LENGTH);     /* size of last block */
    if ( sha_rem == 0 )                 /* last block = SHA_LENGTH */
	{
           sha_block--;
    }
    for ( i = 0; i <= sha_block; i++)
    {
        SHAInit ( &hash_context );
        memcpy( M, RVAL, SHA_LENGTH);
		memset( M + SHA_LENGTH, 0, DSS_LENGTH_MIN - SHA_LENGTH );
        if ( (status = SHAUpdate( &hash_context, M, DSS_LENGTH_MIN ))
                         != SUCCESS )
        {
		    return status;                        /* error */
        }
        if ( (status=MySHAFinal (&hash_context, hash_result )) != SUCCESS )
        {
            return status;                       /* error */
        }
#ifdef CTK_BIG_ENDIAN
		ByteSwap((uchar*)RVAL,SHA_LENGTH);
#endif
        BigSwap((uchar*)RVAL, SHA_LENGTH);
		Sum_Q(RVAL, 1,SHA_LENGTH / sizeof(ord));
		Sum_big( RVAL,                 /* RVAL=RVAL+hash_result*/
				(ord*)hash_result,
					  RVAL, SHA_LENGTH / sizeof(ord) );
        BigSwap((uchar*)RVAL, SHA_LENGTH);
#ifdef CTK_BIG_ENDIAN
        ByteSwap((uchar*)RVAL,SHA_LENGTH);
#endif
         if ( i == sha_block  && sha_rem != 0 )  /* last block < SHA_LENGTH*/
		 {
             memcpy( &A[ i*SHA_LENGTH / sizeof(ord)], hash_result,
                 sha_rem * sizeof (uchar));
         }
		 else                                   /* last block = SHA_LENGTH*/
         {
             memcpy( &A[ i*SHA_LENGTH / sizeof(ord)], hash_result,
                                   SHA_LENGTH * sizeof (uchar));
         }
     }
     return status;
}

