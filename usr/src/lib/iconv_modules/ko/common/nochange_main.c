/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 */


#include <errno.h>
#include <widec.h>
#include "common_def.h"
#include "common_han.h"


/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	return((void*)NULL);

}  /* end of int _icv_open(). */


/****  _ I C V _ C L O S E  ****/

void _icv_close(void* cd)
{
	return;

}  /* end of void _icv_close(_conv_desc*). */


/****  _ I C V _ I C O N V  ****/

size_t _icv_iconv(void* cd, char** inbuf, size_t* inbufleft,
			    char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;

	/*
	 * Simply copy input to output as it is
	 */


	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;

	memcpy((char *)ob, (char *)ib, *inbufleft);

	*inbuf = (char*)(ib + *inbufleft);
	*inbufleft = 0;
	*outbuf = (char*)(ob + *outbufleft) ;
	*outbufleft = 0;

	return(ret_val);

}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*).*/
