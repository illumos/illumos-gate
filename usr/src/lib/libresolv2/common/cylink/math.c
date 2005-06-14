/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
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
*  FILENAME: math.c   PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION: Math Routines for the ToolKit 
*
*  PUBLIC FUNCTIONS:
*
*         int Sum_big (ord *X,
*                      ord *Y,
*                      ord *Z,
*                      u_int16_t len_X )
*
*         int Sub_big (ord *X,
*                      ord *Y,
*                      ord *Z,
*                      u_int16_t len_X )
*
*         void  Mul_big( ord *X, ord *Y,ord *XY,
*                        u_int16_t lx, u_int16_t ly)
*
*
*  PRIVATE FUNCTIONS:
*
*  REVISION  HISTORY:
*
*  14 Oct 94   GKL     Initial release
*  26 Oct 94   GKL     (alignment for big endian support )
*
****************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/
/* bn files */
#include "port_before.h"
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
#include "toolkit.h"
#include "port_after.h"

/****************************************************************************
*   NAME: void BigNumInit( void )
*
*
*  DESCRIPTION:  Initialize BigNum
*
*  INPUTS:
*     PARAMETERS:
*  OUTPUT:
*     PARAMETERS:
*
*     RETURN:
*
*
*  REVISION HISTORY:
*
*  29 Sep 96        Initial release
*
****************************************************************************/

void BigNumInit()
{
static int bignuminit = 0;
if(!bignuminit){
	bnInit();
	bignuminit = 1;
 }
}
/****************************************************************************
*   NAME: int Sum_big (ord *X,
*                      ord *Y,
*                      ord *Z,
*                      u_int16_t len_X )
*
*  DESCRIPTION:  Compute addition.
*
*  INPUTS:
*     PARAMETERS:
*           ord  *X        Pointer to first array
*           ord  *Y        Pointer to second array
*           int  len_X     Number of longs in X_l
*  OUTPUT:
*     PARAMETERS:
*           ord *Z         Pointer to result arrray
*
*     RETURN:
*            Carry bit
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

 int Sum_big (ord *X,
			  ord *Y,
			  ord *Z,
			  u_int16_t len_X )
{

struct BigNum src2,temp_bn;
ord *temp;
BigNumInit();

/*bnInit();
bnBegin(&src2);
bnBegin(&temp_bn);
*/
temp = (ord *) malloc((len_X*sizeof(ord)) + sizeof(ord));
temp_bn.size = len_X;
temp_bn.ptr = temp;
temp_bn.allocated = len_X + 1;

src2.ptr = Y;
src2.size = len_X;
src2.allocated = len_X;

memcpy(temp,X,len_X*sizeof(ord));
bnAdd(&temp_bn,&src2);
memcpy(Z,temp_bn.ptr,len_X*sizeof(ord));
/*bn package increments the size of dest by 1 if the carry bit is 1*/
free(temp);
if (temp_bn.size > len_X)
	return 1;
else
	return 0;
}

 int Sum (ord *X, ord *Y, u_int16_t len_X )
{

struct BigNum dest,src;
/*ord *temp;*/
BigNumInit();
#if 0
bnInit();
bnBegin(&src2);
bnBegin(&temp_bn);

temp = (ord *) malloc((len_X*sizeof(ord)) + sizeof(ord));
temp_bn.size = len_X;
temp_bn.ptr = temp;
temp_bn.allocated = len_X + 1;
#endif

dest.ptr = X;
dest.size = len_X-1;
dest.allocated = len_X;

src.ptr = Y;
src.size = len_X;
src.allocated = len_X;

/*memcpy(temp,X,len_X*sizeof(ord));*/
bnAdd(&dest,&src);
/*memcpy(Z,temp_bn.ptr,len_X*sizeof(ord));*/
/*bn package increments the size of dest by 1 if the carry bit is 1*/
/*free(temp);*/
if (dest.size > (u_int16_t)(len_X -1))
	return 1;
else
	return 0;
}


/****************************************************************************
*   NAME: int Sum_Q(ord *X,
*                      u_int16_t src,
*                      u_int16_t len_X )
*  DESCRIPTION:  Compute addition X += src.
*
*  INPUTS:
*     PARAMETERS:
*           ord  *X        Pointer to first array
*           u_int16_t  src    Second operand must be <65535
*           int  len_X     Number of ords in X_l
*  OUTPUT:
*     PARAMETERS:
*           ord *X         Pointer to result arrray
*
*     RETURN:
*            SUCCESS or -1
*
*  REVISION HISTORY:
*
*  21 Sep 96   AAB     Initial release
****************************************************************************/
 int Sum_Q(ord *X, u_int16_t src, u_int16_t len_X )
 {
  int status = SUCCESS;
  struct BigNum des;
  BigNumInit();
  /*bnInit();*/
  des.ptr = X;
  des.size = len_X;
  des.allocated = len_X;
  status = bnAddQ(&des, src);
  return status;
 }


/****************************************************************************
*  NAME:  int Sub_big (ord *X,
*                      ord *Y,
*                      ord *Z,
*                      u_int16_t len_X )
*
*
*  DESCRIPTION:  Compute subtraction.
*
*  INPUTS:
*     PARAMETERS:
*           ord   *X        Pointer to first array
*           ord   *Y        Pointer to second array
*           u_int16_t   len_X     Number of longs in X_l
*  OUTPUT:
*     PARAMETERS:
*           ord  *Z         Pointer to result arrray
*
*     RETURN:
*            Carry bit
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

int Sub_big  (ord *X,
			  ord *Y,
			  ord *Z,
			  u_int16_t len_X )
{
/* carry is not returned in bn version */
struct BigNum dest, src;
int status;
ord *temp;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src);
*/
src.ptr = Y;
src.size = len_X;
src.allocated = len_X;

temp = (ord*)malloc(len_X*sizeof(ord));
dest.ptr = temp;
dest.size = len_X;
dest.allocated = len_X;
memcpy(dest.ptr,X,len_X*sizeof(ord));

status = bnSub(&dest,&src);
memcpy(Z,dest.ptr,len_X*sizeof(ord));
free(temp);
return status;
}

#if 0
/****************************************************************************
*  NAME:   void  Mul_big( ord  *X, ord *Y, ord *XY,
*                         u_int16_t lx, u_int16_t ly)
*
*
*
*  DESCRIPTION:  Compute a product.
*
*  INPUTS:
*     PARAMETERS:
*            ord  *X                 Pointer to first long array
*            ord  *Y                 Pointer to second long array
*            u_int16_t lx               Leftmost non zero element of first array
*            u_int16_t ly               Leftmost non zero element of second array
*  OUTPUT:
*     PARAMETERS:
*            ord  *XY              Pointer to result
*
*     RETURN:
*
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*  08 Sep 95   AAB     Comment out calloc and discard the elements_in_X,
*                  elements_in_Y
****************************************************************************/
void  Mul_big( ord  *X, ord *Y, ord *XY,
						 u_int16_t lx, u_int16_t ly )
{
struct BigNum dest, src1, src2;
BigNumInit();
/*bnInit();*/
bnBegin(&dest);
/*
bnBegin(&src1);
bnBegin(&src2);
*/
src1.size = lx + 1;
src1.ptr = X;
src1.allocated = lx + 1;

src2.ptr = Y;
src2.size = ly + 1;
src2.allocated = ly + 1;

dest.ptr = XY;
dest.size = lx + ly + 2;
dest.allocated = lx + ly + 2;

/* Call bn routine */
bnMul(&dest, &src1,&src2);
}

#endif
/****************************************************************************
*  NAME:   void  Mul_big_1( ord  X, ord *Y, ord *XY,
*                                 u_int16_t lx, u_int16_t ly )
*
*
*
*  DESCRIPTION:  Compute a product.
*
*  INPUTS:
*     PARAMETERS:
*            ord  X                  Number
*            ord  *Y                 Pointer to long array
*            u_int16_t ly               Leftmost non zero element of second array
*  OUTPUT:
*     PARAMETERS:
*            ord  *XY              Pointer to result
*
*     RETURN:
*
*
*  REVISION HISTORY:
*
*  08 Oct 95   AAB     Initial relaese
*
****************************************************************************/
void  Mul_big_1( ord  X, ord *Y, ord *XY,
				u_int16_t ly )
{
struct BigNum dest, src;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src);
*/
src.ptr = Y;
src.size = ly + 1;
src.allocated = ly + 1;

dest.ptr = XY;
dest.size = ly + 2;
dest.allocated = ly + 2;

bnMulQ(&dest, &src, (unsigned)X);

}

/****************************************************************************
*  NAME: int Mul( u_int16_t X_bytes,
*                 ord        *X,
*                 u_int16_t Y_bytes,
*                 ord       *Y,
*                 u_int16_t P_bytes,
*                 ord   *P,
*                 ord   *Z )
*
*  DESCRIPTION:  Compute a modulo product
*
*  INPUTS:
*      PARAMETERS:
*            ord   *X           Pointer to first operand
*            u_int16_t X_bytes     Number of bytes in X
*            ord   *Y           Pointer to second operand
*            u_int16_t Y_bytes     Number of bytes in Y
*            ord   *P           Pointer to modulo
*            u_int16_t P_bytes     Number of bytes in P
*
*  OUTPUT:
*      PARAMETERS:
*            ord   *Z           Pointer to result
*
*      RETURN:
*          SUCCESS              No errors
*          ERR_INPUT_LEN        Invalid length for input data (zero bytes)
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

int Mul( u_int16_t X_bytes,
			ord *X,
		 u_int16_t Y_bytes,
			ord *Y,
		 u_int16_t P_bytes,
		 ord *P,
		 ord *Z )

{
	int status = SUCCESS;       /*function return status*/
	u_int16_t X_longs;             /*number of longs in X*/
	u_int16_t Y_longs;             /*number of longs in Y*/
	ord *XY;                    /*pointer to product (temporary)*/


struct BigNum dest, src1,src2, mod;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src1);
bnBegin(&src2);
bnBegin(&mod);
*/

src1.size = X_bytes/sizeof(ord);
src1.ptr = X;
src1.allocated = X_bytes/sizeof(ord);

src2.size = Y_bytes/sizeof(ord);
src2.ptr = Y;
src2.allocated =Y_bytes/sizeof(ord);

mod.size = P_bytes/sizeof(ord);
mod.ptr = P;
mod.allocated = P_bytes/sizeof(ord);

	 if ( P_bytes == 0 || X_bytes == 0 || Y_bytes == 0 )
	{
		 status = ERR_INPUT_LEN;
		return status;
	}
	if ( (X_bytes % sizeof(ord) != 0) ||
		  (Y_bytes % sizeof(ord) != 0) ||
		 (P_bytes % sizeof(ord) != 0) )
	{
		 status = ERR_INPUT_LEN;
		return status;
	}
	X_longs = (u_int16_t) (X_bytes / sizeof(ord));
	Y_longs = (u_int16_t) (Y_bytes / sizeof(ord));
	XY = (ord *)calloc( X_longs +  Y_longs, sizeof(ord) );
	if( !XY  )
	{
		return ERR_ALLOC;
	}
dest.size = X_longs + Y_longs;
dest.ptr = XY;
dest.allocated = X_longs + Y_longs;

bnMul (&dest,&src1,&src2);

status = bnMod(&dest, &dest, &mod);
memcpy(Z, dest.ptr, P_bytes);
free( XY );
	return status;
}

/****************************************************************************
*  NAME: int Square( u_int16_t X_bytes,
*                         ord    *X,
*                     u_int16_t P_bytes,
*                        ord    *P,
*                     ord   *Z )
*
*  DESCRIPTION:  Compute a modulo square
*
*  INPUTS:
*      PARAMETERS:
*            ord   *X           Pointer to array to be squared
*            u_int16_t X_bytes     Number of bytes in X
*            ord   *P           Pointer to modulo
*            u_int16_t P_bytes     Number of bytes in P
*
*  OUTPUT:
*      PARAMETERS:
*            ord   *Z           Pointer to result
*
*      RETURN:
*          SUCCESS              No errors
*          ERR_INPUT_LEN        Invalid length for input data (zero bytes)
*
*  REVISION HISTORY:
*
*  1  Sep 95   AAB     Initial release
****************************************************************************/

int Square( u_int16_t X_bytes,
				ord *X,
				u_int16_t P_bytes,
				ord *P,
				ord *Z )

{
	 int status = SUCCESS;       /*function return status*/

ord *XY;
struct BigNum dest, src, mod;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src);
bnBegin(&mod);
*/
	if ( P_bytes == 0 || X_bytes == 0 )
	{
		 status = ERR_INPUT_LEN;
		return status;
	 }
	if ( (X_bytes % sizeof(ord) != 0) ||
		  (P_bytes % sizeof(ord) != 0) )
	 {
		 status = ERR_INPUT_LEN;
		return status;
	 }
	XY = (ord *)malloc( 2*X_bytes );
	 if( !XY )
	 {
		 return ERR_ALLOC;
	 }

src.size = X_bytes/sizeof(ord);
src.ptr = X;
src.allocated = X_bytes/sizeof(ord);

dest.size = 2*X_bytes/sizeof(ord);
dest.ptr = XY;
dest.allocated = 2*X_bytes/sizeof(ord);

mod.size = P_bytes/sizeof(ord);
mod.ptr = P;
mod.allocated = P_bytes/sizeof(ord);

status = bnSquare(&dest, &src);
status = bnMod(&dest, &dest, &mod);
memcpy(Z, dest.ptr, P_bytes);
free(XY);
return status;
}


/****************************************************************************
*  NAME: int PartReduct( u_int16_t X_bytes,
*                        ord  *X,
*                        u_int16_t P_bytes,
*                        ord  *P,
*                        ord *Z )
*
*  DESCRIPTION:  Compute a modulo
*
*  INPUTS:
*      PARAMETERS:
*            ord   *X              Pointer to array
*            u_int16_t X_bytes        Number of bytes in X
*            ord   *P              Pointer to modulo
*            u_int16_t P_bytes        Number of bytes in P
*
*  OUTPUT:
*      PARAMETERS:
*            ord   *Z              Pointer to result
*
*      RETURN:
*          SUCCESS             No errors
*          ERR_INPUT_LEN       Invalid length for input data (zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*
****************************************************************************/

int PartReduct( u_int16_t X_bytes,
	  ord *X,
	  u_int16_t P_bytes,
	  ord   *P,
	  ord   *Z )
{
	 int status = SUCCESS;       /*function return status */


struct BigNum dest, /*src,*/ d;
ord *temp;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src);
bnBegin(&d);

src.size = X_bytes/sizeof(ord);
src.ptr = X;
src.allocated = X_bytes/sizeof(ord);
*/
d.size = P_bytes/sizeof(ord);
d.ptr = P;
d.allocated = P_bytes/sizeof(ord);

temp = (ord*)malloc(X_bytes);
dest.size = X_bytes/sizeof(ord);
dest.ptr = temp;
dest.allocated = X_bytes/sizeof(ord);
memcpy(dest.ptr, X, X_bytes);

status = bnMod(&dest, &dest, &d);

memcpy(Z, dest.ptr, P_bytes);
free(temp);

return status;

}

/****************************************************************************
*  NAME: int Expo( u_int16_t X_bytes,
*                  ord    *X,
*                  u_int16_t Y_bytes,
*                  ord    *Y,
*                  u_int16_t P_bytes,
*                  ord    *P,
*                  ord    *Z,
*                  YIELD_context *yield_cont )
*
*  DESCRIPTION:  Compute a modulo exponent
*
*  INPUTS:
*      PARAMETERS:
*            ord   *X           Pointer to base array
*            u_int16_t X_bytes     Number of bytes in base
*            ord   *Y           Pointer to exponent array
*            u_int16_t Y_bytes     Number of bytes in exponent
*            ord   *P           Pointer to modulo
*            u_int16_t P_bytes     Number of bytes in  P
*            YIELD_context *yield_cont  Pointer to yield_cont structure (NULL if not used)
*
*  OUTPUT:
*      PARAMETERS:
*            ord   *Z            Pointer to result
*
*  RETURN:
*          SUCCESS               No errors
*          ERR_INPUT_LEN         Invalid length for input data(zero bytes)
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*  08 Dec 94   GKL     Added YIELD_context
*  01 Sep 95           Fast exponentation algorithm
****************************************************************************/

int Expo( u_int16_t X_bytes, ord    *X,
		 u_int16_t Y_bytes, ord    *Y,
		 u_int16_t P_bytes, ord    *P,
		 ord   *Z )
{

int status = SUCCESS;     /*function return status*/

struct BigNum dest, n, exp, mod;
BigNumInit();
#if 0
/*bnInit();*/
bnBegin(&dest);
bnBegin(&n);
bnBegin(&exp);
bnBegin(&mod);
#endif

n.size = X_bytes/sizeof(ord);
n.ptr = X;
n.allocated = X_bytes/sizeof(ord);

exp.ptr = Y;
exp.size = Y_bytes/sizeof(ord);
exp.allocated = Y_bytes/sizeof(ord);

mod.ptr = P;
mod.size = P_bytes/sizeof(ord);
mod.allocated = P_bytes/sizeof(ord);

dest.ptr = Z;
dest.size = P_bytes/sizeof(ord);
dest.allocated = P_bytes/sizeof(ord);

/* Call bn routine */

status = bnExpMod(&dest, &n,
				  &exp, &mod);

return status;
}


/****************************************************************************
*  NAME: int DoubleExpo( u_int16_t X1_bytes,
*                  ord    *X1,
*                  u_int16_t Y1_bytes,
*                  ord    *Y1,
*  					 u_int16_t X2_bytes,
*                  ord    *X2,
*                  u_int16_t Y2_bytes,
*                  ord    *Y2,
*                  u_int16_t P_bytes,
*                  ord    *P,
*                  ord    *Z)
*
*  DESCRIPTION:  Compute a modulo exponent
*
*  INPUTS:
*      PARAMETERS:
*            ord   *X1           Pointer to first base array
*            u_int16_t X1_bytes     Number of bytes in first base
*            ord   *Y1           Pointer to first exponent array
*            u_int16_t Y1_bytes     Number of bytes in first exponent
*            ord   *X2           Pointer to second base array
*            u_int16_t X2_bytes     Number of bytes in second base
*            ord   *Y2           Pointer to second exponent array
*            u_int16_t Y2_bytes     Number of bytes in second exponent            ord   *P           Pointer to modulo
*            ord   *P           Pointer to modulo
*            u_int16_t P_bytes     Number of bytes in
*
*  OUTPUT:
*      PARAMETERS:
*            ord   *Z            Pointer to result
*
*  RETURN:
*          SUCCESS               No errors
*          ERR_INPUT_LEN         Invalid length for input data(zero bytes)
*
*  REVISION HISTORY:
*
*  21 Aug 96   AAB     Initial release
****************************************************************************/


int DoubleExpo( u_int16_t X1_bytes,ord    *X1,
					 u_int16_t Y1_bytes,ord    *Y1,
					 u_int16_t X2_bytes,ord    *X2,
					 u_int16_t Y2_bytes,ord    *Y2,
					 u_int16_t P_bytes,ord    *P,
										 ord    *Z)
{
int status = SUCCESS;     /*function return status*/
struct BigNum res, n1, e1, n2, e2, mod;
BigNumInit();

n1.size = X1_bytes/sizeof(ord);
n1.ptr = X1;
n1.allocated = X1_bytes/sizeof(ord);

e1.size = Y1_bytes/sizeof(ord);
e1.ptr = Y1;
e1.allocated = Y1_bytes/sizeof(ord);

n2.size = X2_bytes/sizeof(ord);
n2.ptr = X2;
n2.allocated = X2_bytes/sizeof(ord);

e2.size = Y2_bytes/sizeof(ord);
e2.ptr = Y2;
e2.allocated = Y2_bytes/sizeof(ord);

mod.ptr = P;
mod.size = P_bytes/sizeof(ord);
mod.allocated = P_bytes/sizeof(ord);

res.ptr = Z;
res.size = P_bytes/sizeof(ord);
res.allocated = P_bytes/sizeof(ord);
status = bnDoubleExpMod(&res, &n1, &e1, &n2, &e2, &mod);
return status;
}

/****************************************************************************
*  NAME: int Inverse( u_int16_t X_bytes,
*                     ord    *X,
*                     u_int16_t P_bytes,
*                     ord    *P,
*                     ord    *Z )
*
*
*
*
*  DESCRIPTION:  Compute a modulo inverse element
*
*  INPUTS:
*      PARAMETERS:
*            ord   *X           Pointer to array
*            u_int16_t X_bytes     Number of bytes in array
*            ord   *P           Pointer to modulo
*            u_int16_t P_bytes     Number of bytes in  P
*
*  OUTPUT:
*      PARAMETERS:
*            ord   *Z           Pointer to result
*
*      RETURN:
*          SUCCESS              No errors
*          ERR_INPUT_LEN        Invalid length for input data(zero bytes)
*          ERR_INPUT_VALUE  Invalid input value
*
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ     Initial release
*  14 Oct 94   GKL     Second version (big endian support)
*  08 Nov 94   GKL     Added input parameters check
*  01 Sep 95           Improve fuction
****************************************************************************/

int Inverse( u_int16_t X_bytes,
			  ord    *X,
			  u_int16_t P_bytes,
			 ord    *P,
				ord    *Z )
{
int status = SUCCESS;   /* function return status */

struct BigNum dest, src, mod;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src);
bnBegin(&mod);
*/
src.size = X_bytes/sizeof(ord);
src.ptr = X;
src.allocated = X_bytes/sizeof(ord);

mod.ptr = P;
mod.size = P_bytes/sizeof(ord);
mod.allocated = P_bytes/sizeof(ord);

dest.ptr = Z;
dest.size = (P_bytes/sizeof(ord))  ;
dest.allocated = (P_bytes/sizeof(ord)) + 1;
status = bnInv(&dest,&src,&mod);
return status;
}


/****************************************************************************
*  NAME:     void Add( ord    *X,
*                      ord    *Y,
*                      u_int16_t P_len,
*                      ord    *P,
*                      ord    *Z )

*
*  DESCRIPTION:  Compute modulo addition
*
*  INPUTS:
*          PARAMETERS:
*                         ord   *X              Pointer to first operand
*                         ord   *Y              Pointer to second operand
*                         u_int16_t P_len  Length of modulo
*                         ord   *P              Pointer to modulo
*  OUTPUT:
*             ord   *Z          Pointer to result
*          RETURN:
*
*  REVISION HISTORY:
*
*  24 sep 94    KPZ             Initial release
*  10 Oct 94    KPZ     Fixed bugs
*  14 Oct 94    GKL     Second version (big endian support)
*
****************************************************************************/
 /*
 int Add( ord *X,
		  ord *Y,
	  u_int16_t P_len,
		  ord *P,
			ord *Z )
{
	int status = SUCCESS;
	ord *temp;
	struct BigNum dest, src, mod;

bnInit();
bnBegin(&dest);
bnBegin(&src);
bnBegin(&mod);

temp = (ord*)malloc(P_len + sizeof(ord));
memcpy(temp, X, P_len);

dest.size = P_len/sizeof(ord);
dest.ptr = temp;
dest.allocated = P_len/sizeof(ord) + 1;

src.ptr = Y;
src.size = P_len/sizeof(ord);
src.allocated = P_len/sizeof(ord);

mod.ptr = P;
mod.size = P_len/sizeof(ord);
mod.allocated = P_len/sizeof(ord);

status = bnAdd(&dest,&src);
status = bnMod(&dest,&dest,&mod);
memcpy(Z,temp,P_len);
free(temp);
return status;
}
 */
 int Add( ord *X,
		  ord *Y,
	  u_int16_t P_len,
		  ord *P)
{
	int status = SUCCESS;
/*	ord *temp;*/
	struct BigNum dest, src, mod;

BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&src);
bnBegin(&mod);
*/
/*
temp = (ord*)malloc(P_len + sizeof(ord));
memcpy(temp, X, P_len);
*/
dest.size = P_len/sizeof(ord);
/*dest.ptr = temp;*/
dest.ptr = X;
dest.allocated = P_len/sizeof(ord) + 1;

src.ptr = Y;
src.size = P_len/sizeof(ord);
src.allocated = P_len/sizeof(ord);

mod.ptr = P;
mod.size = P_len/sizeof(ord);
mod.allocated = P_len/sizeof(ord);

status = bnAdd(&dest,&src);
status = bnMod(&dest,&dest,&mod);
/*
memcpy(Z,temp,P_len);
free(temp);
*/
return status;
}




/****************************************************************************
*  NAME:     int SteinGCD( ord *m,
*                          ord *b
*                          u_int16_t len )
*
*  DESCRIPTION:  Compute great common divisor
*
*  INPUTS:
*          PARAMETERS:
*           ord *m           Pointer to first number
*           ord *b           Pointer to second number
*           u_int16_t len       Number of elements in number
*  OUTPUT:
*
*  RETURN:
*           TRUE                   if gcd != 1
*           FALSE                                  if gcd == 1
*  REVISION HISTORY:
*
*
*  24 Sep 94    KPZ     Initial release
*  14 Oct 94    GKL     Second version (big endian support)
*  01 Sep 95    AAB     Speed up
*
****************************************************************************/


/* test if GCD equal 1 */
int  SteinGCD ( ord  *m,
		  ord  *n,
				u_int16_t len )
{

int status;
struct BigNum dest, a, b;
ord *temp;
BigNumInit();
/*bnInit();
bnBegin(&dest);
bnBegin(&a);
bnBegin(&b);
*/
a.size = len;
a.ptr = m;
a.allocated = len;

b.size = len;
b.ptr = n;
b.allocated = len;

temp = (ord*)malloc((len+1)*sizeof(ord));
dest.size = len;
dest.ptr = temp;
dest.allocated = len+1;

status = bnGcd(&dest, &a, &b);

if (*(ord *)(dest.ptr) == 0x01 && dest.size == 1)
 status = 0;
else
 status = 1;

free(temp);

return status;

}


/****************************************************************************
*  NAME: int DivRem( u_int16_t X_bytes,
*                    ord    *X,
*                    u_int16_t P_bytes,
*                    ord    *P,
*                    ord    *Z,
*                    ord    *D)
*
*  DESCRIPTION:  Compute a modulo and quotient
*
*  INPUTS:
*          PARAMETERS:
*                    ord   *X              Pointer to array
*                    u_int16_t X_bytes        Number of bytes in X
*                    ord   *P              Pointer to modulo
*                    u_int16_t P_bytes        Number of bytes in  P
*
*  OUTPUT:
*          PARAMETERS:
*            ord   *Z              Pointer to result
*            ord   *D                      Pointer to quotient
*          RETURN:
*                  SUCCESS             No errors
*          ERR_INPUT_LEN       Invalid length for input data (zero bytes)
*  REVISION HISTORY:
*
*  24 Sep 94   KPZ              Initial release
*  10 Oct 94   KPZ      Fixed bugs
*  14 Oct 94   GKL      Second version (big endian support)
*
****************************************************************************/

int DivRem( u_int16_t X_bytes,
		 ord    *X,
	  u_int16_t P_bytes,
		 ord    *P,
	  ord    *Z,
	  ord    *D)
{
	int status = SUCCESS;       /* function return status */

struct BigNum q, r, /*n,*/ d;
ord *temp;
BigNumInit();
/*bnInit();
bnBegin(&q);
bnBegin(&r);
bnBegin(&n);
bnBegin(&d);

n.size = X_bytes/sizeof(ord);
n.ptr = X;
n.allocated = X_bytes/sizeof(ord);
*/
d.size = P_bytes/sizeof(ord);
d.ptr = P;
d.allocated = P_bytes/sizeof(ord);

q.size = (X_bytes/sizeof(ord)) - (P_bytes/sizeof(ord)) + 1;
q.ptr = D;
q.allocated = (X_bytes/sizeof(ord)) - (P_bytes/sizeof(ord)) + 1;

temp = (ord *)malloc(X_bytes);
r.size = X_bytes/sizeof(ord);
r.ptr = temp;
r.allocated = X_bytes/sizeof(ord);
memcpy(r.ptr, X, X_bytes);

status = bnDivMod(&q, &r, &r, &d);

memcpy(Z, r.ptr, P_bytes);
free(temp);

return status;

}
