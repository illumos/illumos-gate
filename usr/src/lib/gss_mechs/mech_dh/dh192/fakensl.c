/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	fakensl.c
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <rpc/rpc.h>
#include <rpc/key_prot.h>

#ifndef HEX_KEY_BYTES
#define	HEX_KEY_BYTES HEXKEYBYTES
#endif

extern int key_encryptsession_pk(const char *, netobj *, des_block *);
extern int key_decryptsession_pk(const char *, netobj *, des_block *);

/*ARGSUSED*/
int
__getpublickey_cached_g(const char remotename[], int keylen,
    int algtype, char *pkey, size_t pkeylen, int *cached)
{
	return (getpublickey(remotename, pkey));
}

#pragma weak getpublickey_g
/*ARGSUSED*/
int
getpublickey_g(const char remotename[], int keylen,
    int algtype, char *pkey, size_t pkeylen)
{
	return (getpublickey(remotename, pkey));
}

#pragma weak key_encryptsession_pk_g
/*ARGSUSED*/
int
key_encryptsession_pk_g(const char *remotename, const char *pk, int keylen,
    int algtype, des_block deskeys[], int no_keys)
{
	int i;
	netobj npk;

	npk.n_len = HEX_KEY_BYTES;
	npk.n_bytes = (char *)pk;

	for (i = 0; i < no_keys; i++) {
		if (key_encryptsession_pk(remotename, &npk, &deskeys[i]))
			return (-1);
	}
	return (0);
}

#pragma weak key_decryptsession_pk_g
/*ARGSUSED*/
int
key_decryptsession_pk_g(const char *remotename, const char *pk, int keylen,
    int algtype, des_block deskeys[], int no_keys)
{
	int i;
	netobj npk;

	npk.n_len = HEX_KEY_BYTES;
	npk.n_bytes = (char *)pk;

	for (i = 0; i < no_keys; i++) {
		if (key_decryptsession_pk(remotename, &npk, &deskeys[i]))
			return (-1);
	}
	return (0);
}

#pragma weak key_gendes_g
int
key_gendes_g(des_block deskeys[], int no_keys)
{
	int i;

	memset(deskeys, 0, no_keys* sizeof (des_block));
	for (i = 0; i < no_keys; i++) {
		if (key_gendes(&deskeys[i]))
			return (-1);
	}
	return (0);
}

#pragma weak key_secretkey_is_set_g
/*ARGSUSED*/
int
key_secretkey_is_set_g(int Keylen, int algtype)
{
	return (key_secretkey_is_set());
}

#pragma weak des_setparity
void
des_setparity_g(des_block *key)
{
	des_setparity((char *)key);
}
