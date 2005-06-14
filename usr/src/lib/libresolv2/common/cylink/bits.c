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
*  FILENAME: bit.c   PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:  Bit Utility Functions
*
*  PUBLIC FUNCTIONS:
*
*
*  PRIVATE FUNCTIONS:
*
*  REVISION  HISTORY:
*
*
****************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/
/* bn files */
#include "port_before.h"
#include <sys/types.h>
#include "bn.h"
/* system files */
#ifdef VXD
#include <vtoolsc.h>
#else
#include <stdlib.h>
#include <string.h>
#endif
/* program files */
#include "cylink.h"
#include "ctk_endian.h"
#include "c_asm.h"
#include "port_after.h"


/****************************************************************************
*  NAME: void  RShiftL( ord   *X,
*                       u_int32_t  len_X,
*                       u_int32_t  n_bit )
*
*  DESCRIPTION:  Shift array to the right by n_bit.
*
*  INPUTS:
*          PARAMETERS:
*            ord  *X            Pointer to array
*            u_int32_t len_X         Length of array
*                        u_int32_t n_bit             Number of bits
*  OUTPUT:
*          PARAMETERS:
*            ord  *X            Pointer to array
*
*          RETURN:
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/

void  RShiftL_big( ord   *X,
	           u_int32_t  len_X,
  		   u_int32_t  n_bit )
{

struct BigNum dest;
bnInit();
bnBegin(&dest);

dest.ptr = X;
dest.size = len_X;
dest.allocated = len_X;

bnRShift(&dest,n_bit);

}

/****************************************************************************
*  NAME: void  LShiftL( ord   *X,
*                       u_int32_t  len_X,
*                       u_int32_t  n_bit )
*
*  DESCRIPTION:  Shifts array to the left by n_bit.
*
*  INPUTS:
*          PARAMETERS:
*            ord  *X            Pointer to array
*            u_int32_t len_X         Length of array
*                        u_int32_t n_bit             Number of bits
*  OUTPUT:
*          PARAMETERS:
*            ord  *X            Pointer to array
*
*          RETURN:
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/

void  LShiftL_big( ord *X,
			   u_int32_t len_X,
		   u_int32_t n_bit )
{
struct BigNum dest;
bnInit();
bnBegin(&dest);

dest.ptr = X;
dest.size = len_X;
dest.allocated = len_X;

bnLShift(&dest,n_bit);
}

/************9****************************************************************
*  NAME:     int RShiftMostBit( ord *a,
*                                                       u_int32_t len )
*
*  DESCRIPTION:  Find a least significant non zero bit
*                                and sfift array to the right
*
*  INPUTS:
*          PARAMETERS:
*           ord *a           Pointer to array
*           u_int32_t len         Number of elements in number
*  OUTPUT:
*
*  RETURN:
*            Number of shifted bits
*
*  REVISION HISTORY:
*
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/

int RShiftMostBit( ord *a,
			 u_int32_t len )
{

struct BigNum n;
bnInit();
bnBegin(&n);

n.size = len;
n.ptr = a;
n.allocated = len;

return (bnMakeOdd(&n));

}


/****************************************************************************
*  NAME:   void  ByteLong (uchar *X, u_int32_t X_bytes,
*                                    u_int32_t  *Y )
*
*
*  DESCRIPTION:  Transfer bytes to u_int32_t.
*
*  INPUTS:
*          PARAMETERS:
*            uchar  *X            Pointer to byte array
*            u_int32_t X_bytes   Number of bytes in array
*  OUTPUT:
*          PARAMETERS:
*            u_int32_t *Y         Pointer to long arrray
*
*          RETURN:
*
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

void  ByteLong( uchar *X,
                u_int32_t X_bytes,
                u_int32_t *Y )
{
    u_int32_t i, j;                    /* counters */
    for ( i = 0, j = 0; j < X_bytes; i++, j += 4)
    {
				Y[i] = ( (u_int32_t)X[j] ) | ( ((u_int32_t)X[j+1]) << 8 ) |
                     ( ((u_int32_t)X[j+2]) << 16 ) | ( ((u_int32_t)X[j+3]) << 24 );
	}
}

/****************************************************************************
*  NAME:   void  ByteOrd (uchar *X, u_int32_t X_bytes,
*                                   ord   *Y )
*
*
*  DESCRIPTION:  Transfer bytes to ord.
*
*  INPUTS:
*          PARAMETERS:
*            uchar  *X            Pointer to byte array
*            u_int32_t X_bytes   Number of bytes in array
*  OUTPUT:
*          PARAMETERS:
*            ord *Y         Pointer to long array
*
*          RETURN:
*
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

void  ByteOrd( uchar *X,
               u_int32_t X_bytes,
               ord *Y )
{
    u_int32_t i, j;                    /* counters */
	for ( i = 0, j = 0; j < X_bytes; i++, j += sizeof(ord))
    {
              Y[i] = ( (ord)X[j] ) | ( ((ord)X[j+1]) << 8 )
#ifdef ORD_32
          | ( ((ord)X[j+2]) << 16 ) | ( ((ord)X[j+3]) << 24 )
#endif
            ;
    }
}

/****************************************************************************
*  NAME:   void  OrdByte (ord *X, u_int32_t X_bytes,
*                                 uchar  *Y )
*
*
*  DESCRIPTION:  Transfer ord to bytes.
*
*  INPUTS:
*          PARAMETERS:
*            ord  *X            Pointer to ord array
*            u_int32_t X_bytes     Number of bytes in array
*  OUTPUT:
*          PARAMETERS:
*            uchar *Y         Pointer to byte array
*
*          RETURN:
*
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

void  OrdByte( ord *X,
               u_int32_t X_bytes,
               uchar *Y )
{
    u_int32_t i, j;              /* counters */
    for ( i=0, j=0; j < X_bytes; i++, j += sizeof(ord))
    {
			  Y[j] = (uchar ) ( X[i] & 0xff );
				Y[j+1] = (uchar)( (X[i] >> 8) & 0xff );
#ifdef ORD_32
        Y[j+2] = (uchar)( (X[i] >> 16) & 0xff );
        Y[j+3] = (uchar)( (X[i] >> 24) & 0xff );
#endif
    }
}

/****************************************************************************
*  NAME: void  LongByte( u_int32_t  *X,
*                        u_int32_t X_bytes,
*                        uchar  *Y )
*
*  DESCRIPTION:  Transfer u_int32_t to bytes.
*
*  INPUTS:
*          PARAMETERS:
*            u_int32_t  *X            Pointer to long array
*            u_int32_t X_bytes   Number of longs in array
*  OUTPUT:
*          PARAMETERS:
*            uchar *Y         Pointer to bytes array
*
*          RETURN:
*
*
*  REVISION HISTORY:
*
*  24 Sep 94    KPZ             Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/

void  LongByte( u_int32_t *X,
				u_int32_t X_bytes,
                uchar  *Y )
{
    u_int32_t i, j;              /* counters */
    for ( i=0, j=0; j < X_bytes; i++, j += 4)
    {
            Y[j] = (uchar ) ( X[i] & 0xff );
        Y[j+1] = (uchar)( (X[i] >> 8) & 0xff );
        Y[j+2] = (uchar)( (X[i] >> 16) & 0xff );
		Y[j+3] = (uchar)( (X[i] >> 24) & 0xff );
    }
}


