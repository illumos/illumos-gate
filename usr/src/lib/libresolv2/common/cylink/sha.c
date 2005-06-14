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
*  FILENAME:  cencrint.c   PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:             Cryptographic Toolkit Internal Functions File
*
*  PRIVATE FUNCTIONS:
*
*
*               void shaTransform( u_int32_t *state, uchar *block )
*               void SHAInitK( SHA_context *hash_context )
*               int MySHA( uchar *message, u_int16_t message_bytes,
*                          uchar *hash_result )
*               int MySHAFinal( SHA_context *hash_context, uchar *hash_result )
*
*
*       Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
*
*  24 Sep 94   KPZ   Initial release
*  10 Oct 94   KPZ   Fixed bugs in Add(), DivRem()
*  12 Oct 94   KPZ   Modified shaTransform()
*  14 Oct 94   GKL   Second version (big endian support)
*  26 Oct 94   GKL   (alignment for big endian support & ERR_ALLOC)
*  08 Nov 94   GKL      Added input parameters check to Inverse
*  08 Dec 94   GKL   Added YIELD_context to Expo, VerPrime and GenPrime
*
****************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/

#include "port_before.h"
#include <sys/types.h>

/* system files */
#ifdef VXD
#include <vtoolsc.h>
#else
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif

/* program files */
#include "cylink.h"
#include "ctk_endian.h"
#include "toolkit.h"
#include "cencrint.h"
#include "sha.h"
#include "port_after.h"
extern u_int16_t DataOrder;

/****************************************************************************
*  NAME:  int SHA( uchar   *message,
*                  u_int16_t message_bytes,
*                  uchar  *hash_result )
*
*  DESCRIPTION:  Compute a Secure Hash Function.
*
*  INPUTS:
*      PARAMETERS:
*         uchar *message          Pointer to message
*         u_int16_t message_bytes    Number of bytes in message
*         uchar *hash_result      Pointer to message digest
*
*  OUTPUT:
*      PARAMETERS:
*         uchar *hash_result      Message digest
*
*      RETURN:
*          SUCCESS                 No errors
*          ERR_INPUT_LEN           Invalid length for input data(zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ     Initial release
*
****************************************************************************/

int SHA( uchar   *message,
         u_int16_t message_bytes,
         uchar  *hash_result )
{
     SHA_context hash_context;     /* SHA context structure */
    int status = SUCCESS;         /* function return status */
    if (message_bytes == 0 )
    {
        status = ERR_INPUT_LEN;
        return status;            /* invalid length for input data */
    }
    SHAInit ( &hash_context );    /* initialize SHA */
    if ( (status = SHAUpdate( &hash_context, message, message_bytes ))
          != SUCCESS )
    {
       return status;            /* error */
    }
    if ((status=SHAFinal (&hash_context, hash_result)) != SUCCESS )
    {
       return status;           /* error */
    }

    return status;
}

/****************************************************************************
*  PRIVATE FUNCTIONS DEFINITIONS
****************************************************************************/


/****************************************************************************
*  NAME:     void shaTransform( u_int32_t *state,
*                               uchar *block )
*
*  DESCRIPTION:  Perform  SHS transformation.
*
*  INPUTS:
*          PARAMETERS:
*           SHA_context *hash_context  Pointer to SHA_context structure
*  OUTPUT:
*
*           SHA_context *hash_context  Pointer to SHA_context structure
*                                      (updated)
*  REVISION HISTORY:
*
*  24 sep 94    KPZ     Initial release
*  12 Oct 94    KPZ     Modified buffers copy
*  14 Oct 94    GKL     Second version (big endian support)
*  1  Sep 95    AAB     Speedup the function
****************************************************************************/

 void shaTransform( u_int32_t *state,
					const uchar *block )
{
   u_int32_t W[80];
   u_int32_t A,B,C,D,E;  /*,temp;*/
   memcpy( W, block, 64);                 /*TKL00201*/
#ifdef CTK_LITTLE_ENDIAN                      /*TKL00201*/
      ByteSwap32( (uchar *)W, 64);        /*TKL00201*/
#endif                                    /*TKL00201*/
   /* Expand the 16 words into 80 words */
   expand(16);expand(17);expand(18);expand(19);expand(20);expand(21);
   expand(22);expand(23);expand(24);expand(25);expand(26);expand(27);
   expand(28);expand(29);expand(30);expand(31);expand(32);expand(33);
   expand(34);expand(35);expand(36);expand(37);expand(38);expand(39);
   expand(40);expand(41);expand(42);expand(43);expand(44);expand(45);
   expand(46);expand(47);expand(48);expand(49);expand(50);expand(51);
   expand(52);expand(53);expand(54);expand(55);expand(56);expand(57);
   expand(58);expand(59);expand(60);expand(61);expand(62);expand(63);
   expand(64);expand(65);expand(66);expand(67);expand(68);expand(69);
   expand(70);expand(71);expand(72);expand(73);expand(74);expand(75);
   expand(76);expand(77);expand(78);expand(79);
  /*Set up first buffer*/
         A = state[0];
   B = state[1];
   C = state[2];
   D = state[3];
   E = state[4];

 /* Heavy mangling, in 4 sub-rounds of 20 iterations each. */
    subRound( A, B, C, D, E, f1, k1SHA, W[ 0] );
    subRound( E, A, B, C, D, f1, k1SHA, W[ 1] );
    subRound( D, E, A, B, C, f1, k1SHA, W[ 2] );
    subRound( C, D, E, A, B, f1, k1SHA, W[ 3] );
    subRound( B, C, D, E, A, f1, k1SHA, W[ 4] );
	subRound( A, B, C, D, E, f1, k1SHA, W[ 5] );
    subRound( E, A, B, C, D, f1, k1SHA, W[ 6] );
	subRound( D, E, A, B, C, f1, k1SHA, W[ 7] );
    subRound( C, D, E, A, B, f1, k1SHA, W[ 8] );
    subRound( B, C, D, E, A, f1, k1SHA, W[ 9] );
    subRound( A, B, C, D, E, f1, k1SHA, W[10] );
    subRound( E, A, B, C, D, f1, k1SHA, W[11] );
    subRound( D, E, A, B, C, f1, k1SHA, W[12] );
    subRound( C, D, E, A, B, f1, k1SHA, W[13] );
    subRound( B, C, D, E, A, f1, k1SHA, W[14] );
    subRound( A, B, C, D, E, f1, k1SHA, W[15] );
	subRound( E, A, B, C, D, f1, k1SHA, W[16] );
    subRound( D, E, A, B, C, f1, k1SHA, W[17] );
	subRound( C, D, E, A, B, f1, k1SHA, W[18] );
    subRound( B, C, D, E, A, f1, k1SHA, W[19] );

    subRound( A, B, C, D, E, f2, k2SHA, W[20]);
     subRound( E, A, B, C, D, f2, k2SHA, W[21]);
     subRound( D, E, A, B, C, f2, k2SHA, W[22]);
     subRound( C, D, E, A, B, f2, k2SHA, W[23]);
     subRound( B, C, D, E, A, f2, k2SHA, W[24]);
     subRound( A, B, C, D, E, f2, k2SHA, W[25]);
	 subRound( E, A, B, C, D, f2, k2SHA, W[26]);
     subRound( D, E, A, B, C, f2, k2SHA, W[27]);
	 subRound( C, D, E, A, B, f2, k2SHA, W[28]);
     subRound( B, C, D, E, A, f2, k2SHA, W[29]);
     subRound( A, B, C, D, E, f2, k2SHA, W[30]);
     subRound( E, A, B, C, D, f2, k2SHA, W[31]);
     subRound( D, E, A, B, C, f2, k2SHA, W[32]);
     subRound( C, D, E, A, B, f2, k2SHA, W[33]);
     subRound( B, C, D, E, A, f2, k2SHA, W[34]);
     subRound( A, B, C, D, E, f2, k2SHA, W[35]);
     subRound( E, A, B, C, D, f2, k2SHA, W[36]);
	 subRound( D, E, A, B, C, f2, k2SHA, W[37]);
     subRound( C, D, E, A, B, f2, k2SHA, W[38]);
	 subRound( B, C, D, E, A, f2, k2SHA, W[39]);

     subRound( A, B, C, D, E, f3, k3SHA, W[40]);
     subRound( E, A, B, C, D, f3, k3SHA, W[41]);
     subRound( D, E, A, B, C, f3, k3SHA, W[42]);
     subRound( C, D, E, A, B, f3, k3SHA, W[43]);
     subRound( B, C, D, E, A, f3, k3SHA, W[44]);
     subRound( A, B, C, D, E, f3, k3SHA, W[45]);
     subRound( E, A, B, C, D, f3, k3SHA, W[46]);
	 subRound( D, E, A, B, C, f3, k3SHA, W[47]);
     subRound( C, D, E, A, B, f3, k3SHA, W[48]);
	 subRound( B, C, D, E, A, f3, k3SHA, W[49]);
     subRound( A, B, C, D, E, f3, k3SHA, W[50]);
     subRound( E, A, B, C, D, f3, k3SHA, W[51]);
     subRound( D, E, A, B, C, f3, k3SHA, W[52]);
     subRound( C, D, E, A, B, f3, k3SHA, W[53]);
     subRound( B, C, D, E, A, f3, k3SHA, W[54]);
     subRound( A, B, C, D, E, f3, k3SHA, W[55]);
     subRound( E, A, B, C, D, f3, k3SHA, W[56]);
     subRound( D, E, A, B, C, f3, k3SHA, W[57]);
	 subRound( C, D, E, A, B, f3, k3SHA, W[58]);
     subRound( B, C, D, E, A, f3, k3SHA, W[59]);

     subRound( A, B, C, D, E, f4, k4SHA, W[60]);
     subRound( E, A, B, C, D, f4, k4SHA, W[61]);
     subRound( D, E, A, B, C, f4, k4SHA, W[62]);
     subRound( C, D, E, A, B, f4, k4SHA, W[63]);
     subRound( B, C, D, E, A, f4, k4SHA, W[64]);
     subRound( A, B, C, D, E, f4, k4SHA, W[65]);
     subRound( E, A, B, C, D, f4, k4SHA, W[66]);
     subRound( D, E, A, B, C, f4, k4SHA, W[67]);
	 subRound( C, D, E, A, B, f4, k4SHA, W[68]);
     subRound( B, C, D, E, A, f4, k4SHA, W[69]);
	 subRound( A, B, C, D, E, f4, k4SHA, W[70]);
     subRound( E, A, B, C, D, f4, k4SHA, W[71]);
     subRound( D, E, A, B, C, f4, k4SHA, W[72]);
     subRound( C, D, E, A, B, f4, k4SHA, W[73]);
     subRound( B, C, D, E, A, f4, k4SHA, W[74]);
     subRound( A, B, C, D, E, f4, k4SHA, W[75]);
     subRound( E, A, B, C, D, f4, k4SHA, W[76]);
     subRound( D, E, A, B, C, f4, k4SHA, W[77]);
     subRound( C, D, E, A, B, f4, k4SHA, W[78]);
	 subRound( B, C, D, E, A, f4, k4SHA, W[79]);

	 state[0] += A;
  state[1] += B;
  state[2] += C;
  state[3] += D;
  state[4] += E;

}




/****************************************************************************
*  NAME:  void SHAInitK( SHA_context *hash_context )
*
*  DESCRIPTION: Initialize Secure Hash Function for generate
*               random number for DSS.
*
*  INPUTS:
*          PARAMETERS:
*              SHA_context *hash_context   SHA context structure
*  OUTPUT:
*          PARAMETERS:
*             SHA_context *hash_context    Initialized SHA context structure
*
*          RETURN:
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/

void SHAInitK( SHA_context *hash_context )
{
/*Set up first buffer*/
  /* on28 port: silence compiler warnings by changing 0x...L to 0x...U */
   hash_context->state[0] = 0xEFCDAB89U;
   hash_context->state[1] = 0x98BADCFEU;
   hash_context->state[2] = 0x10325476U;
   hash_context->state[3] = 0xC3D2E1F0U;
   hash_context->state[4] = 0x67452301U;
/*Initialise buffer */
   memset( hash_context->buffer, 0, sizeof(hash_context->buffer));
   memset( hash_context->count, 0,  sizeof(hash_context->count));
}


/****************************************************************************
*  NAME:  int MySHA( uchar   *message,
*                    u_int16_t message_bytes,
*                    uchar  *hash_result )
*
*  DESCRIPTION:  Compute a Secure Hash Function.
*
*  INPUTS:
*          PARAMETERS:
*                 uchar *message          Pointer to message
*                 u_int16_t message_bytes    Number of bytes in message
*         uchar *hash_result      Pointer to message digest
*
*  OUTPUT:
*          PARAMETERS:
*         uchar *hash_result      Message digest
*
*          RETURN:
*                  SUCCESS                 No errors
*          ERR_INPUT_LEN           Invalid length for input data(zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*
****************************************************************************/
int MySHA( uchar   *message,
           u_int16_t message_bytes,
      uchar  *hash_result )
{
       SHA_context hash_context;     /* SHA context structure */
       int status = SUCCESS;         /* function return status */
	  if (message_bytes == 0 )
        {
               status = ERR_INPUT_LEN;
         return status;            /* invalid length for input data */
   }
       SHAInit ( &hash_context );    /* initialize SHA */
#ifdef CTK_BIG_ENDIAN
    ByteSwap(message,message_bytes);
#endif
    status = SHAUpdate( &hash_context, message, message_bytes );
#ifdef CTK_BIG_ENDIAN
	ByteSwap(message,message_bytes);
#endif
    if ( status != SUCCESS )
    {
			   return status;            /* error */
   }
    if ((status=MySHAFinal (&hash_context, hash_result)) != SUCCESS )
  {
               return status;           /* error */
    }
       return status;
}

/****************************************************************************
*  NAME:  int MySHAFinal( SHA_context *hash_context,
*                         uchar       *hash_result )
*  DESCRIPTION:  Finalize Secure Hash Function
*
*  INPUTS:
*          PARAMETERS:
*              SHA_context *hash_context    SHA context structure
*                uchar *hash_result     Pointer to hash
*  OUTPUT:
*          PARAMETERS:
*              uchar *hash_result        Final value
*          RETURN:
*                  SUCCESS               No errors
*          ERR_INPUT_LEN         Invalid length for input data (zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ         Initial release
*  10 Oct 94   KPZ     Modified for arbitrary message length
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/
  int MySHAFinal( SHA_context *hash_context,
             uchar       *hash_result )
{
   int status = SUCCESS;         /* function return status */
      uchar bits[8];
  u_int16_t index, padLen;
   u_int32_t ex;
       uchar PADDING[64] = {         /* padding string */
              0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
 };

	  if ( hash_context->count[0] == 0 && hash_context->count[1] == 0 )
       {
          status= ERR_INPUT_LEN;
          return status;
       }
 /* Save number of bits */
     LongByte( &hash_context->count[1] , 4, bits );
  LongByte( &hash_context->count[0] , 4, bits + 4 );
      ByteSwap32( bits, 8 );
 /* Pad out to 56 mod 64.*/
   index = (u_int16_t )((hash_context->count[0] >> 3) & 0x3f);
		padLen = (u_int16_t) ((index < 56) ? (56 - index) : (120 - index));
   SHAUpdate( hash_context, PADDING, padLen );

 /* Append length (before padding) */
    SHAUpdate (hash_context, bits, 8);

 /* Set order of hash_context */
	ex = hash_context->state[0];
  hash_context->state[0] = hash_context->state[4];
    hash_context->state[4] = ex;
    ex = hash_context->state[1];
	hash_context->state[1] = hash_context->state[3];
    hash_context->state[3] = ex;
  /* Store state in digest */
    memcpy(hash_result,hash_context->state,SHA_LENGTH);
  /* Zeroize sensitive information.*/
    memset( hash_context, 0, sizeof(hash_context) );
#if defined ( ORD_16 )  && defined( CTK_BIG_ENDIAN )
	WordSwap(hash_result,SHA_LENGTH);
#endif
    return status;
}


/****************************************************************************
*  NAME:  int SHAUpdate( SHA_context *hash_context,
*                        uchar        *message,
*                        u_int16_t      message_bytes )
*  DESCRIPTION:  Update Secure Hash Function
*
*  INPUTS:
*      PARAMETERS:
*          SHA_context *hash_context        SHA context structure
*          uchar       *message             Pointer to message
*          u_int16_t       message_bytes       Number of bytes
*  OUTPUT:
*      PARAMETERS:
*          SHA_context  *hash_context       Updated SHA context structure
*
*      RETURN:
*          SUCCESS          No errors
*          ERR_INPUT_LEN    Invalid length for input data (zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ      Initial release
*  10 Oct 94   KPZ      Modified for arbitrary message length
*
****************************************************************************/

int SHAUpdate( SHA_context *hash_context,
            const uchar        *message,
          u_int16_t      message_bytes )

{
    int status = SUCCESS;         /* function return status */
    u_int16_t i, index, partLen;
    if ( message_bytes == 0 )
    {
        status = ERR_INPUT_LEN;   /*invalid length for input data (zero bytes)*/
        return status;
    }

  /* Compute number of bytes mod 64 */
    index = (u_int16_t)((hash_context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
    if ( (hash_context->count[0] += ((u_int32_t )message_bytes << 3))
              < ((u_int32_t )message_bytes << 3) )
    {
   hash_context->count[1]++;
    }
    hash_context->count[1] += ((u_int32_t )message_bytes >> 29);

    partLen = (u_int16_t) (64 - index);
  /* Transform as many times as possible.*/
    if ( message_bytes >= partLen )
    {
  memcpy( &hash_context->buffer[index], message, partLen );
       shaTransform( hash_context->state, hash_context->buffer );

      for ( i = partLen; (u_int16_t)(i + 63) < message_bytes; i += 64 )
  {
           shaTransform ( hash_context->state, &message[i] );
  }
       index = 0;
    }
    else
    {
     i = 0;
    }
  /* Buffer remaining input */
    memcpy( &hash_context->buffer[index], &message[i],
             message_bytes - i );
    return status;
}


/****************************************************************************
*  NAME:  void SHAInit( SHA_context *hash_context )
*
*  DESCRIPTION:  Initialize Secure Hash Function
*
*  INPUTS:
*      PARAMETERS:
*              SHA_context *hash_context   SHA context structure
*  OUTPUT:
*      PARAMETERS:
*             SHA_context *hash_context    Initialized SHA context structure
*
*      RETURN:
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ     Initial release
*
****************************************************************************/

void SHAInit( SHA_context *hash_context )
{
/*Set up first buffer*/
    hash_context->state[0] = h0SHA;
    hash_context->state[1] = h1SHA;
    hash_context->state[2] = h2SHA;                  
    hash_context->state[3] = h3SHA;
    hash_context->state[4] = h4SHA;

/* Initialise buffer */
    memset( hash_context->buffer, 0, sizeof(hash_context->buffer));
 /*Initialize bit count*/
    hash_context->count[0] = hash_context->count[1] = 0;
}

/****************************************************************************
*  NAME:  int SHAFinal( SHA_context *hash_context,
*                       uchar       *hash_result )
*  DESCRIPTION:  Finalize Secure Hash Function
*
*  INPUTS:
*      PARAMETERS:
*          SHA_context *hash_context    SHA context structure
*                uchar *hash_result     Pointer to hash
*  OUTPUT:
*      PARAMETERS:
*              uchar *hash_result        Final value
*      RETURN:
*          SUCCESS               No errors
*          ERR_INPUT_LEN         Invalid length for input data (zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  10 Oct 94   KPZ     Modified for arbitrary message length
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/


int SHAFinal( SHA_context *hash_context,
                                uchar       *hash_result )
{
    int status = SUCCESS;         /* function return status */
    status =  MySHAFinal( hash_context, hash_result );
#ifdef CTK_BIG_ENDIAN
    if (status == SUCCESS)
    {
        ByteSwap(hash_result, SHA_LENGTH);
    }
#endif
    if (DataOrder)
    {
        BigSwap(hash_result, SHA_LENGTH);
    }
    return status;
}

/****************************************************************************
*  NAME: int GetPasswordKeySHA( u_int16_t Password_bytes,
*                               uchar  *Password,
*                               uchar  *salt,
*                               u_int16_t Count,
*                               uchar  *K,
*                               uchar  *IV )
*
*  DESCRIPTION: Get Password-Based DES/KAPPA Key by SHA
*
*  INPUTS:
*      PARAMETERS:
*            u_int16_t Password_bytes    Number of bytes in password
*            uchar  *Password         Pointer to password
*            uchar  *salt             Pointer to salt(8-byte)
*            u_int16_t Count             Number of iteration
*  OUTPUT:
*      PARAMETERS:
*            uchar *K                Pointer to DES/KAPPA key
*            uchar *IV               Pointer to initialization vector
*      RETURN:
*          SUCCESS              No errors
*          ERR_COUNT            Invalid iteration count (zero)
*          ERR_INPUT_LEN        Invalid length for input data(zero bytes)
*          ERR_ALLOC            Insufficient memory
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  26 Oct 94   GKL     (ERR_ALLOC)
*
****************************************************************************/
 int GetPasswordKeySHA( u_int16_t Password_bytes,
                        uchar  *Password,
                        uchar  *salt,
                        u_int16_t Count,
                        uchar  *K,
                        uchar  *IV )

{
    int status = SUCCESS;      /* function return status */
    uchar digest[SHA_LENGTH];
        uchar *buf;
    if ( Count == 0 )          /* invalid iteration count (zero) */
    {
        status = ERR_COUNT;
        return status;
    }
    CALLOC(buf,uchar,Password_bytes + 8);
    if ( status !=  SUCCESS )
    {
       return status;     /* ERR_ALLOC   insufficient memory */
    }
    if ( Password_bytes != 0 )  /* if number of bytes password non equals zero */
        {
    memcpy( buf, Password, Password_bytes );
    }
    memcpy( buf + Password_bytes, salt, 8);
/* Compute message digest */
    status = SHA( buf, (u_int16_t)(Password_bytes + 8), digest);
    if (!DataOrder)
    {
        BigSwap(digest, SHA_LENGTH);
    }

    if ( status != SUCCESS )
    {
        free ( buf );
        return status;
    }
    Count --;            /* decrement Count */
/* Count times compute message digest */
    while ( Count != 0 )
    {
        if ( (status = SHA( digest, SHA_LENGTH, digest)) != SUCCESS )
        {
            free ( buf );
            return status;
        }
        if (!DataOrder)
        {
            BigSwap(digest, SHA_LENGTH);
        }
        Count --;
    }
    memcpy( K, digest, 8 );
    memcpy( IV, digest + SHA_LENGTH -8, 8 );
    free ( buf );
    return status;
}
