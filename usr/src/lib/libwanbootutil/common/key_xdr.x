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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #ident	"%Z%%M%	%I%	%E% SMI" */

/*
 * The formal definition of OIDs comes from ITU-T recommendation X.208
 */
const	WBKU_AES_128_OID = "2.16.840.1.101.3.4.1.2";
const	WBKU_DES3_OID = "1.3.6.1.4.1.4929.1.8";
const	WBKU_HMAC_SHA1_OID = "1.3.6.1.5.5.8.1.2";
const	WBKU_RSA_OID = "1.2.840.113549.1.1.1";

const	WBKU_MAX_KEYLEN = 1024;

struct wbku_key {
	bool	wk_master;
	string	wk_oid<>;
	opaque	KEYDATA<WBKU_MAX_KEYLEN>;
};

#ifdef	RPC_HDR
%#define wk_key_len KEYDATA.KEYDATA_len
%#define wk_key_val KEYDATA.KEYDATA_val
#endif	/* RPC_HDR */

/*
 * Allow one entry for each key that can be in a keystore at
 * the same time.  There can be one AES key, one 3DES key,
 * two HMAC SHA-1 values (one master and one for the client) and one RSA
 * private key. The master key is a HMAC SHA-1 master key used to
 * derive a per-client HMAC SHA-1 key as described in RFC 3118, Appendix A.
 */
typedef struct wbku_key wbku_keystore<5>;
