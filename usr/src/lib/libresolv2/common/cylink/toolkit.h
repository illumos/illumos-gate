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
*  FILENAME:  toolkit.h       PRODUCT NAME: CRYPTOGRAPHIC TOOLKIT
*
*  FILE STATUS:
*
*  DESCRIPTION:     Cryptographic Toolkit Functions Header File
*
*  USAGE:            File should be included to use Toolkit Functions
*
*
*         Copyright (c) Cylink Corporation 1994. All rights reserved.
*
*  REVISION  HISTORY:
*
*  23 Aug 94  KPZ     Initial release
*  24 Sep 94    KPZ Added prototypes of Toolkit functions
*  14 Oct 94    GKL Second version (big endian support)
*  08 Dec 94    GKL Added YIELD_context to GenDSSParameters
*
****************************************************************************/

#ifndef TOOLKIT_H     /* Prevent multiple inclusions of same header file */
#define TOOLKIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Error types */

#define SUCCESS       0      /* no errors */
#define ERR_DATA -1      /* generic data error */
#define ERR_ALLOC       -2      /* insufficient memory */
#define ERR_INPUT_LEN  -3      /* invalid length for input data (zero bytes) */
#define ERR_DSS_LEN     -4      /* invalid length for dss_p */
#define ERR_DH_LEN        -5      /* invalid length for DH_modulus */
#define ERR_BLOCK_LEN     -7      /* invalid length for input block for ECB/CBC */
#define ERR_HASH_LEN    -8      /* invalid length for hash_result */
#define ERR_MODE    -9      /* invalid value of encryption mode */
#define ERR_NUMBER        -10     /* invalid number of testings (zero) */
#define ERR_POSITION     -11     /* invalid value of  triplet_position   */
#define ERR_COUNT     -12     /* invalid iteration count (zero) */
#define ERR_SIGNATURE       -21     /* signature is not valid */
#define ERR_PRIME       -22     /* number is not prime */
#define ERR_WEAK        -23     /* weak key */
#define ERR_INPUT_VALUE -24     /* invalid input value */
/* additional error types for CEPA */
#define ERR_KEY_LENGTH  -25     /* invalid value of key length */
#define ERR_ROUNDS      -26     /* invalid value of rounds number */
#define ERR_CANCEL      -30     /* canceled by user */
#define ERR_MODULUS_ZERO -31    /* invalid modulo */
#define ERR_UNSUPPORTED  -40     /* unsupported crypto method */
#define ERR_OP_CODE		 -41		/*invalid operation code*/



/* Lengths of variables */
#define DH_LENGTH_MIN    64  /* 512-bit minimal length for DH functions */
#define DSS_LENGTH_MIN   64  /* 512-bit minimal length for DSS functions */
#define DSS_LENGTH_MAX  128  /* 1024-bit maximal length for DSS functions */
#define SHA_LENGTH       20  /* 160-bit length for SHA hash result */

/* Number of random bases for Miller test */
#define TEST_COUNT        40

#define LITTLE_ORDER 0
#define BIG_ORDER    1

/* Key lengths */      /* add to toolkit.h */
#define KEY_40BIT   40  /* 40-bit key */
#define KEY_64BIT   64  /* 64-bit key */
#define KEY_128BIT  128  /* 128-bit key */
#define CEPA_MAX_ROUNDS 12

/* Operation codes for MultiPrecArithm() */
#define EXPO	0x21
#define MUL		0x22
/*#define ADD		0x23*/

/****************************************************************************
*  INCLUDE FILES
****************************************************************************/

/* system files */
#include "cylink.h"
#include "ctk_endian.h"
/* callback function */
#ifdef VXD
typedef int (* YIELD_PROC)( void );
#else
typedef int (* YIELD_PROC)(int ); /*TKL00601*/
#endif

typedef struct {                   /*TKL00601*/
       YIELD_PROC yield_proc;
  void *     handle;         /* Application specific information */
}YIELD_context;


/* Secure Hash Algorithm structure */
typedef struct
{
    u_int32_t state[ 5 ];      /* state */
      u_int32_t count[ 2 ];          /* number of bits */
 uchar buffer[ 64 ];     /* input buffer */
} SHA_context;


#ifdef  __cplusplus
extern  "C" {
#endif
/* Copy Cylink DSS Common Parameters */    /*TKL01201*/
   int GetDSSPQG(u_int16_t dss_p_bytes,
                 uchar  *dss_p,
          uchar  *dss_q,
          uchar  *dss_g);

/* Compute a Secure Hash Function */
 int SHA( uchar   *message, u_int16_t message_bytes,
									uchar  *hash_result );
/* Initialize Secure Hash Function */
 void SHAInit( SHA_context *hash_context );

/* Update Secure Hash Function */
 int SHAUpdate( SHA_context *hash_context,
                const uchar        *message,
                u_int16_t      message_bytes );
/* Finalize Secure Hash Function */
 int SHAFinal( SHA_context *hash_context,
               uchar       *hash_result );
/* Compute a DSS Signature */
 int GenDSSSignature( u_int16_t dss_p_bytes, uchar  *dss_p,
                uchar  *dss_q,      uchar  *dss_g,
                      uchar  *dss_x,      uchar  *dss_k,
                      uchar  *r,          uchar  *s,
                      uchar  *hash_result );
/* Verify a DSS Signature */
 int VerDSSSignature( u_int16_t dss_p_bytes, uchar  *dss_p,
                      uchar  *dss_q,      uchar  *dss_g,
                      uchar  *dss_y,      uchar  *r,
                      uchar  *s,          uchar  *hash_result);
/* Initialize Random number Generator */
 int InitRand( u_int16_t SEED_bytes, uchar  *SEED,
											 uchar  *RVAL );
/* Generate random number */
 int GenRand( u_int16_t A_bytes, uchar  *A,
                           uchar  *RVAL );
/* Compute DSS public/secret number pair */
 int GenDSSKey( u_int16_t dss_p_bytes, uchar  *dss_p,
                uchar  *dss_q,      uchar  *dss_g,
                uchar  *dss_x,      uchar  *dss_y,
                                    uchar  *XKEY );
/* Generate secret number */
 int GenDSSNumber( uchar *dss_k, uchar *dss_q,
                                                              uchar *KKEY );

/* Compute a Diffie-Hellman Shared number */
 int GetDHSharedNumber( u_int16_t DH_modulus_bytes, uchar  *DH_secret,
                        uchar  *DH_public,       uchar  *DH_shared,
                        uchar  *DH_modulus );
/* Set Key by Diffie_Hellman shared number */
 int SetDESKAPPAKey( u_int16_t DH_modulus_bytes, uchar  *DH_shared,
                     uchar  *K );
/* Expand DES key */
 void DESKeyExpand( uchar *key, uchar *K1 );

/* Encrypt a block of data with single DES */
 int DESEncrypt( uchar  *des_iv,       uchar  *des_key,
                 u_int16_t des_mode,      uchar  *input_array,
                 uchar  *output_array, u_int16_t input_array_bytes );

/* Decrypt a block of data with single DES */
 int DESDecrypt( uchar  *des_iv,  uchar  *des_key,
                 u_int16_t des_mode, uchar  *data_array,
                                 u_int16_t data_array_bytes );

/* One-Time-Pad Signature with a Diffie-Hellman shared number */
 int DHOneTimePad( u_int16_t DH_modulus_bytes, uchar  *DH_shared,
                   uchar  *X,               uchar  *Y );

/* Compute a Diffie-Hellman pair */
 int GenDHPair( u_int16_t DH_modulus_bytes, uchar  *DH_secret,
               uchar  *DH_public,       uchar  *DH_base,
               uchar  *DH_modulus,      uchar  *RVAL );

 int GetPasswordKeySHA( u_int16_t Password_bytes, uchar  *Password,
                                               uchar  *salt,          u_int16_t Count,
                                            uchar  *K,             uchar  *IV );

/* Generate DSS Common Parameters */
 int GenDSSParameters( u_int16_t dss_p_bytes, uchar  *dss_p,
                                          uchar  *dss_q,      uchar  *dss_g,
                                      uchar  *RVAL, YIELD_context *yield_cont ); /*TKL00701*/

/* Produce a Shamir Key-Sharing Triplet for Secret Number */
int GenShamirTriplet( u_int16_t SecretNumber_bytes, uchar *SecretNumber,
                                       uchar *first_value,        uchar *second_value,
													  uchar *third_value,        uchar *RVAL );

/* Reconstract a Secret Number from Shamir Key-Sharing Duplex */
int GetNumberShamirDuplex( u_int16_t SecretNumber_bytes,
                              uchar  *value_A,
                                u_int16_t A_position,                                                      uchar  *value_B,
                                u_int16_t B_position,
                              uchar  *SecretNumber );
int SFDHEncrypt( u_int16_t DH_modulus_bytes,
                                          uchar  *DH_modulus,
                                     uchar  *DH_base,
                                        uchar  *DH_public,
												  uchar  *DH_random_public,
													uchar  *DH_shared,
												  uchar  *RVAL );
int SFDHDecrypt( u_int16_t DH_modulus_bytes,
													 uchar  *DH_modulus,
												 uchar  *DH_secret,
												  uchar  *DH_random_public,
													uchar  *DH_shared );
/* Check DES key weakness */
int CheckDESKeyWeakness( uchar *key );

int SetCipherKey( u_int16_t DH_shared_bytes,
				  uchar  *DH_shared,
				 uchar  *Key,
				 u_int16_t cryptoMethod );
/* Non-Pipelined Triple DES encrypt*/
int TDESEncrypt( uchar  *des_iv,
						 uchar  *des_key1,uchar *des_key2, uchar *des_key3,
						 u_int16_t des_mode,
						 uchar  *input_array,
						 uchar  *output_array,
						 u_int16_t input_array_bytes );
/* Non-Pipelined Triple DES decrypt*/
int TDESDecrypt( uchar  *des_iv,
						 uchar  *des_key1,uchar *des_key2, uchar *des_key3,
						 u_int16_t des_mode,
						 uchar  *data_array,
						 u_int16_t data_array_bytes );
/*Pipeline Triple DES encrypt*/
int PTDESEncrypt( uchar  *iv1, uchar *iv2, uchar *iv3,
						uchar  *des_key1,uchar *des_key2, uchar *des_key3,
						u_int16_t des_mode,
						uchar  *input_array,
						uchar  *output_array,
						u_int16_t input_array_bytes );
/*Pipeline Triple DES decrypt*/
int PTDESDecrypt( uchar  *iv1, uchar *iv2, uchar *iv3,
						uchar  *des_key1,uchar *des_key2, uchar *des_key3,
						u_int16_t des_mode,
						uchar  *data_array,
						u_int16_t input_array_bytes );
 int PCBC1Encrypt( uchar  *iv1, uchar *iv2, uchar *iv3,
						uchar  *des_key1,uchar *des_key2, uchar *des_key3,
						uchar  *msg1,uchar *msg2, uchar *msg3,
						uchar  *out1,uchar *out2, uchar *out3,
						u_int16_t input_array_bytes );
 int PCBC1Decrypt( uchar  *iv1, uchar *iv2, uchar *iv3,
						uchar  *des_key1,uchar *des_key2, uchar *des_key3,
						uchar  *out1,uchar *out2, uchar *out3,
						u_int16_t input_array_bytes );

/*CEPA enc/dec */
int CepaKeyExpand( uchar *key,
					u_int16_t key_length,
					u_int16_t number_of_rounds,
					uchar *expanded_key );

int CepaCsp( u_int16_t key_length,
			  uchar *csp);

int CepaEncrypt( uchar  *iv,
				uchar  *key,
				u_int16_t mode,
				uchar  *csp,
				u_int16_t r,
				uchar  *input_array,
				uchar  *output_array,
				u_int16_t input_array_bytes );

int CepaDecrypt( uchar  *iv,
				uchar  *key,
				u_int16_t mode,
				uchar  *csp,
				u_int16_t r,
				uchar  *data_array,
				u_int16_t data_array_bytes );
void BigNumInit(void);
void SetDataOrder ( u_int16_t dataOrder);

int GetDHSecretShared( u_int16_t DH_modulus_bytes, u_int16_t DH_secret_bytes, uchar  *DH_secret,
                       uchar  *DH_public,       uchar  *DH_shared,
                       uchar  *DH_modulus);
int GenDHKey( u_int16_t DH_modulus_bytes, u_int16_t DH_secret_bytes, uchar  *DH_secret,
             uchar  *DH_public,       uchar  *DH_base,
             uchar  *DH_modulus,      uchar  *RVAL );
int SFDHInitiate( u_int16_t DH_modulus_bytes, u_int16_t DH_secret_bytes,
                       uchar  *DH_modulus, uchar  *DH_base,
                       uchar  *DH_public, uchar  *DH_random_public,
                       uchar  *DH_shared, uchar  *RVAL );
int SFDHComplete( u_int16_t DH_modulus_bytes, u_int16_t DH_secret_bytes,
                       uchar  *DH_modulus,
                       uchar  *DH_secret, uchar  *DH_random_public,
                       uchar  *DH_shared );

int SplitKey( u_int16_t Secretnumber_bytes, uchar *SecretNumber,
              uchar *first_value,       uchar *second_value,
              uchar *third_value,      uchar *RVAL );
int UnsplitKey( u_int16_t Secretnumber_bytes, uchar  *value_A,
                u_int16_t A_position,        uchar  *value_B,
                u_int16_t B_position,        uchar  *SecretNumber );
int SAFERKeyExpand( uchar *key, u_int16_t key_length,
        uchar *expanded_key );
int SAFEREncrypt( uchar  *iv, uchar  *key, u_int16_t mode, u_int16_t key_length, 
               uchar  *input_array, uchar  *output_array, u_int16_t input_array_bytes );
int SAFERDecrypt( uchar  *iv, uchar  *key, u_int16_t mode, u_int16_t r_length,
               uchar  *data_array, u_int16_t data_array_bytes );


	void ByteSwap( uchar  *X, u_int16_t X_len);
	void ByteSwap32( uchar  *X, u_int16_t X_len);
	void WordSwap( uchar  *X, u_int16_t X_len);
	void BigSwap( uchar *buffer, u_int16_t bufferLength);
	 int Sum_big (ord *X, ord *Y, ord *Z, u_int16_t len_X);
	 int Sum_Q(ord *X, u_int16_t src, u_int16_t len_X);
	void  LShiftL_big( ord *X, u_int32_t len_X, u_int32_t n_bit );
	int Sub_big  (ord *X, ord *Y, ord *Z, u_int16_t len_X);
	int DivRem( u_int16_t X_bytes, ord *X, u_int16_t P_bytes, ord *P,
		   ord *Z, ord *D);
	int  SteinGCD (ord *m, ord *n, u_int16_t len);
	 int Add( ord *X, ord *Y, u_int16_t P_len, ord *P);
	int Inverse(u_int16_t X_bytes, ord *X, u_int16_t P_bytes, ord *P,
		    ord *Z);
	int DoubleExpo(u_int16_t X1_bytes, ord *X1, u_int16_t Y1_bytes,
		       ord *Y1, u_int16_t X2_bytes, ord *X2,
		       u_int16_t Y2_bytes, ord *Y2, u_int16_t P_bytes,
		       ord *P, ord *Z);
	int Sum (ord *X, ord *Y, u_int16_t len_X);
	void  Mul_big_1( ord  X, ord *Y, ord *XY, u_int16_t ly);
	int Mul( u_int16_t X_bytes, ord *X, u_int16_t Y_bytes, ord *Y,
                 u_int16_t P_bytes, ord *P, ord *Z );

	int Square(u_int16_t X_bytes, ord *X, u_int16_t P_bytes, ord *P,
		   ord *Z);

	int PartReduct(u_int16_t X_bytes, ord *X, u_int16_t P_bytes, ord *P,
			 ord *Z);
	int Expo(u_int16_t X_bytes, ord *X, u_int16_t Y_bytes, ord *Y,
		 u_int16_t P_bytes, ord *P, ord *Z);


#ifdef  __cplusplus
}
#endif


#endif /* TOOLKIT_H */

