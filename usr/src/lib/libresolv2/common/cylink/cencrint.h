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
*  FILENAME:  cencrint.h      PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:     Cryptographic Toolkit Internal Functions Header File
*
*  USAGE:           File should be included to use Toolkit Functions
*
*
*         Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
*  23 Aug 94  KPZ     Initial release
*  24 Sep 94    KPZ     Added prototypes of internal functions
*  14 Oct 94    GKL     Second version (big endian support)
*  08 Dec 94    GKL             Added YIELD_context to Expo, VerPrime and GenPrime
*
****************************************************************************/

#ifndef CENCRINT_H     /* Prevent multiple inclusions of same header file */
#define CENCRINT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/

/* system files */
#include <sys/types.h>
#include "cylink.h"
#include "ctk_endian.h"
#include "toolkit.h"

#ifdef  __cplusplus
extern  "C" {
#endif

/* Compute a modulo */
 int PartReduct( u_int16_t X_bytes, ord   *X,
                 u_int16_t P_bytes, ord   *P,
               ord   *Z );

/* Compute a modulo product */
 int Mul( u_int16_t X_bytes, ord   *X,
     u_int16_t Y_bytes, ord   *Y,
       u_int16_t P_bytes, ord   *P,
       ord   *Z );
/*Compute a modulo squaring*/
int Mul_Squr( u_int16_t X_bytes, ord    *X,
            u_int16_t P_bytes, ord    *P,
				  ord    *Z );
int Square( u_int16_t X_bytes,
				ord *X,
				u_int16_t P_bytes,
				ord *P,
				ord *Z );

/*Compare two array*/
int Comp_Mont ( ord *X, ord *P, u_int16_t P_longs );
/*Compute invers element*/
ord Inv_Mont ( ord x );
/*Modulo by the Mongomery*/
void PartReduct_Mont( ord *X, u_int16_t P_bytes, ord  *P, ord inv );
/*Computes squaring by the Mongomery modulo*/
int Mul_Squr_Mont(ord    *X, u_int16_t P_bytes,
            ord    *P, ord    *Z,
           ord     inv );
/*Computes multiply by the montgomery modulo*/
int Mul_Mont( ord    *X, ord    *Y,
				 u_int16_t P_bytes, ord    *P,
				  ord    *Z, ord     inv );

/* Compute a modulo exponent */
 int Expo( u_int16_t X_bytes, ord   *X,
			  u_int16_t Y_bytes, ord   *Y,
			  u_int16_t P_bytes, ord   *P,
				ord   *Z );
 /*Compute double exponent */
 int DoubleExpo( u_int16_t X1_bytes,ord    *X1,
					 u_int16_t Y1_bytes,ord    *Y1,
					 u_int16_t X2_bytes,ord    *X2,
					 u_int16_t Y2_bytes,ord    *Y2,
					 u_int16_t P_bytes,ord    *P,
										 ord    *Z);
/* Compute a modulo inverse element */
 int Inverse( u_int16_t X_bytes, ord   *X,
				 u_int16_t P_bytes, ord   *P,
       ord   *Z );

/* Verify Pseudo Prime number */
 int VerPrime( u_int16_t P_bytes, ord    *P,
             u_int16_t k,       ord    *RVAL,
           YIELD_context *yield_cont ); /*TKL00601*/

/* Generate Random Pseudo Prime number */
 int GenPrime( u_int16_t P_bytes, ord    *P,
             u_int16_t k,       ord    *RVAL,
           YIELD_context *yield_cont ); /*TKL00601*/

/* Transfer bytes to u_int32_t */
 void  ByteLong( uchar *X,
          u_int16_t X_bytes,
                 u_int32_t *Y );

/* Transfer u_int32_t to bytes */
 void  LongByte( u_int32_t *X,
              u_int16_t X_bytes,
                 uchar  *Y );

/* Transfer bytes to ord */
  void  ByteOrd( uchar *X,
               u_int16_t X_bytes,
                 ord *Y );

/* Transfer ord to bytes */
  void  OrdByte( ord *X,
            u_int16_t X_bytes,
                 uchar *Y );

/* Find the left most non zero bit */
 int LeftMostBit ( ord X );

/* Find the left most element */
 int LeftMostEl( ord *X,
             u_int16_t len_X );

/* Shift array to rigth by n_bit */
 void  RShiftL( ord   *X,
            u_int16_t  len_X,
          u_int16_t  n_bit );

/* Shifts array to left by n_bit */
 void  LShiftL( ord  *X,
             u_int16_t len_X,
           u_int16_t n_bit );

/* Find the value of bit */
 int BitValue( ord *X,
               u_int16_t n_bits );

/* Perform byte reversal on an array of ordinar type (longword or shortword) */
 void ByteSwap( uchar  *X,
                                u_int16_t X_len );

/* Perform byte reversal on an array from LSB to MSB */
 void BigSwap( uchar  *X,
                                u_int16_t X_len );

/* Perform byte reversal on an array of longword */
 void ByteSwap32( uchar  *X,
                            u_int16_t X_len );

/* Perform short reversal on an array of longword */
 void WordSwap( uchar  *X,
                         u_int16_t X_len );

/* Perform  SHS transformation */
 void shaTransform( u_int32_t *state,
                                       const uchar *block );

/* Compute modulo addition
 int Add( ord    *X,
						 ord    *Y,
				  u_int16_t P_len,
						 ord    *P,
				  ord    *Z );
 */
 int Add( ord    *X,
						 ord    *Y,
				  u_int16_t P_len,
						 ord    *P );
/*  Initialize Secure Hash Function for generate
 random number for DSS                                           */
 void SHAInitK( SHA_context *hash_context );

/* Set parity bits */
 void SetKeyParity( uchar *key );

/*  Find a least significant non zero bit
      and sfift array to right            */
 int RShiftMostBit( ord *a, u_int16_t len );

/*Compute great common divisor */
 int SteinGCD( ord *m, ord *b, u_int16_t len );

/* Compute a modulo and divisor */
 int DivRem( u_int16_t X_bytes, ord    *X,
             u_int16_t P_bytes, ord    *P,
             ord    *Z,      ord    *D );

/* Generate random number */
int MyGenRand( u_int16_t A_bytes, ord    *A,
                               ord    *RVAL);

/* Compute a Secure Hash Function */
int MySHA( uchar   *message,
    u_int16_t message_bytes,
           uchar  *hash_result );

/* Finalize Secure Hash Function */
 int MySHAFinal( SHA_context *hash_context,
          uchar       *hash_result );

 void shaTransform_new( u_int32_t *state,
                   uchar *block );


#ifdef  __cplusplus
}
#endif


#endif /* CENCRINT_H */

