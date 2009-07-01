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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Contains the encryption routines required by the server
 *	and the client-side for NIS+ passwd update deamon.
 */

#include "mt.h"
#include <string.h>
#include <memory.h>
#include <rpc/des_crypt.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nispasswd.h>

/*
 * For export control reasons, we want to limit the maximum size of
 * data that can be encrypted or decrypted to 128 bytes.  The pass-phrase
 * should never be greater then 128 bytes.
 */
#define	MAX_KEY_CRYPT_LEN	128

/*
 * encrypt/decrypt ID (val1) and R (val2)
 * return FALSE on failure and TRUE on success
 */
bool_t
__npd_ecb_crypt(
	uint32_t	*val1,
	uint32_t	*val2,
	des_block	*buf,
	unsigned int	bufsize,
	unsigned int	mode,
	des_block	*deskey)
{
	int	status;
	int32_t	*ixdr;


	if (bufsize > MAX_KEY_CRYPT_LEN)
		return (FALSE);
	ixdr = (int32_t *)buf;
	if (mode == DES_ENCRYPT) {
		(void) memset((char *)buf, 0, bufsize);
		IXDR_PUT_U_INT32(ixdr, *val1);
		IXDR_PUT_U_INT32(ixdr, *val2);

		status = ecb_crypt((char *)deskey, (char *)buf,
		    bufsize, mode | DES_HW);
		if (DES_FAILED(status))
			return (FALSE);
	} else {
		status = ecb_crypt((char *)deskey, (char *)buf,
		    bufsize, mode | DES_HW);

		if (DES_FAILED(status))
			return (FALSE);

		*val1 = IXDR_GET_U_INT32(ixdr);
		*val2 = IXDR_GET_U_INT32(ixdr);
	}
	return (TRUE);
}

/*
 * encrypt/decrypt R (val) and password (str)
 * return FALSE on failure and TRUE on success
 */
bool_t
__npd_cbc_crypt(
	uint32_t	*val,
	char	*str,
	unsigned int	strsize,
	npd_newpass	*buf,
	unsigned int	bufsize,
	unsigned int	mode,
	des_block	*deskey)
{
	int	status, i;
	int32_t	*ixdr;
	des_block	ivec;

	ivec.key.low = ivec.key.high = 0;
	ixdr = (int32_t *)buf;
	if (mode == DES_ENCRYPT) {
		if ((strsize + 4) > bufsize)
			return (FALSE);
		IXDR_PUT_U_INT32(ixdr, *val);
		(void) strcpy((char *)buf->pass, str);
		for (i = strsize; i < __NPD_MAXPASSBYTES; i++)
			buf->pass[i] = '\0';

		status = cbc_crypt((char *)deskey, (char *)buf,
		    bufsize, mode | DES_HW, (char *)&ivec);
		if (DES_FAILED(status))
			return (FALSE);
	} else {
		status = cbc_crypt((char *)deskey, (char *)buf,
		    bufsize, mode | DES_HW, (char *)&ivec);

		if (DES_FAILED(status))
			return (FALSE);

		*val = IXDR_GET_U_INT32(ixdr);
		if (strlen((char *)buf->pass) > strsize)
			return (FALSE);
		(void) strcpy(str, (char *)buf->pass);
	}
	return (TRUE);
}

/*
 * encrypt/decrypt R (val) and password (str)
 * return FALSE on failure and TRUE on success
 */
bool_t
__npd2_cbc_crypt(
	uint32_t	*val,
	char		*str,
	unsigned int	strsize,
	npd_newpass2	*buf,
	unsigned int	bufsize,
	unsigned int	mode,
	des_block	*deskey)
{
	int	status, i;
	int32_t	*ixdr;
	des_block	ivec;

	ivec.key.low = ivec.key.high = 0;
	ixdr = (int32_t *)buf;
	if (mode == DES_ENCRYPT) {
		if ((strsize + 8) > bufsize)
			return (FALSE);
		IXDR_PUT_U_INT32(ixdr, *val);
		(void) strcpy((char *)buf->pass, str);
		for (i = strsize; i < __NPD2_MAXPASSBYTES; i++)
			buf->pass[i] = '\0';
		buf->npd_pad = 0;
		status = cbc_crypt((char *)deskey, (char *)buf,
		    bufsize, mode | DES_HW, (char *)&ivec);
		if (DES_FAILED(status))
			return (FALSE);
	} else {
		status = cbc_crypt((char *)deskey, (char *)buf,
		    bufsize, mode | DES_HW, (char *)&ivec);

		if (DES_FAILED(status))
			return (FALSE);

		*val = IXDR_GET_U_INT32(ixdr);
		if (strlen((char *)buf->pass) > strsize)
			return (FALSE);
		(void) strcpy(str, (char *)buf->pass);
	}
	return (TRUE);
}
