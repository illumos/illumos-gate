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
 *	dh_nsl_tmpl.c
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Entry points for key generation for libnsl. This file should
 * be included in the file that defines the MODULUS, ROOT, and KEYLEN
 * for an algorithm 0 mechanism.
 */


/*
 * The libnsl routine __gen_common_dhkeys_g generate a set of DES
 * keys based on the DH common key given the ALGTYPE and KEYLEN. That
 * routine will construct the mechanism name from those inputs and
 * dlopen the mechanism library to grab this routine with dlsym. This
 * routine will then be used to generate the common key from the
 * supplied public key, private key, and passwd. This routine is
 * just a wrapper to call the generic algorithm 0 key generation
 * routine found in generic_key.c with KEYLEN and MODULUS specified.
 */

void
__dl_gen_common_dhkeys(char *xpublic, char *xsecret,
    des_block keys[], int keynum)
{
	__generic_common_dhkeys(xpublic, xsecret, KEYLEN,
				MODULUS, keys, keynum);
}

/*
 * The libnsl routine __gen_dhkeys_g generate a key pair for a given
 * ALGTYPE and KEYLEN.  That routine will construct the mechanism
 * name from those inputs and dlopen the mechanism to grab this routine. It
 * will then use this routine to generate the key pair. This routine
 * is just a wrapper that marshels the MODULUS, ROOT, and KEYLEN to the
 * generic algorithm 0 key generation routine found in generic_key.c
 */

void
__dl_gen_dhkeys(char *xpublic, char *xsecret, char *passwd)
{
	__generic_gen_dhkeys(KEYLEN, MODULUS, ROOT, xpublic, xsecret, passwd);
}
