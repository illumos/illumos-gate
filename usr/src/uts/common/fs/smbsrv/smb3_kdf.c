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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2020-2023 RackTop Systems, Inc.
 */

#include <smbsrv/smb_kcrypt.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/debug.h>

/*
 * Derive SMB3 key as described in [MS-SMB2] 3.1.4.2
 * and [NIST SP800-108]
 *
 * r = 32, PRF = HMAC-SHA256, key = (session key),
 * L = 128 or 256
 */

/*
 * SMB 3.0.2 KDF Input
 *
 * Session.SigningKey for binding a session:
 * - Session.SessionKey as K1
 * - label = "SMB2AESCMAC" (size 12)
 * - context = "SmbSign" (size 8)
 * Channel.SigningKey for for all other requests
 * - if SMB2_SESSION_FLAG_BINDING, GSS key (in Session.SessionKey?) as K1;
 * - otherwise, Session.SessionKey as K1
 * - label = "SMB2AESCMAC" (size 12)
 * - context = "SmbSign" (size 8)
 * Session.ApplicationKey for ... (not sure what yet)
 * - Session.SessionKey as K1
 * - label = "SMB2APP" (size 8)
 * - context = "SmbRpc" (size 7)
 * Session.EncryptionKey for encrypting server messages
 * - Session.SessionKey as K1
 * - label = "SMB2AESCCM" (size 11)
 * - context = "ServerOut" (size 10)
 * Session.DecryptionKey for decrypting client requests
 * - Session.SessionKey as K1
 * - label = "SMB2AESCCM" (size 11)
 * - context = "ServerIn " (size 10) (Note the space)
 */

/*
 * SMB 3.1.1 KDF Input
 *
 * Session.SigningKey for binding a session:
 * - Session.SessionKey as K1
 * - label = "SMBSigningKey" (size 14)
 * - context = preauth hashval
 * Channel.SigningKey for for all other requests
 * - if SMB2_SESSION_FLAG_BINDING, GSS key (in Session.SessionKey?) as K1;
 * - otherwise, Session.SessionKey as K1
 * - label = "SMBSigningKey" (size 14)
 * - context = preauth hashval
 * Session.EncryptionKey for encrypting server messages
 * - Session.SessionKey as K1
 * - label = "SMBS2CCipherKey" (size 16)
 * - context = preauth hashval
 * Session.DecryptionKey for decrypting client requests
 * - Session.SessionKey as K1
 * - label = "SMBC2SCipherKey" (size 16)
 * - context = preauth hashval
 */

#define	KDF_LABEL_MAXLEN	16
#define	KDF_CONTEXT_MAXLEN	64
#define	KDF_FIXEDPART_LEN	9
#define	KDF_BUFLEN		89	/* total of above */

/*
 * SMB3KDF(Ki, Label, Context)
 * counter || Label || 0x00 || Context || L
 */
int
smb3_kdf(uint8_t *outbuf, uint32_t keylen,
    uint8_t *ssn_key, size_t ssn_keylen,
    uint8_t *label, size_t label_len,
    uint8_t *context, size_t context_len)
{
	smb_crypto_mech_t mech;
	smb_crypto_param_t param;
	uint8_t kdfbuf[KDF_BUFLEN];
	uint32_t L = keylen << 3; /* key len in bits */
	int pos = 0;
	int rc;

	if (label_len > KDF_LABEL_MAXLEN ||
	    context_len > KDF_CONTEXT_MAXLEN) {
		ASSERT(0);
		return (-1);
	}

	/* Counter=1 (big-endian) */
	kdfbuf[pos++] = 0;
	kdfbuf[pos++] = 0;
	kdfbuf[pos++] = 0;
	kdfbuf[pos++] = 1;

	bcopy(label, &kdfbuf[pos], label_len);
	pos += label_len;

	kdfbuf[pos++] = 0;

	bcopy(context, &kdfbuf[pos], context_len);
	pos += context_len;

	/* Key length in bits, big-endian, possibly misaligned */
	kdfbuf[pos++] = 0;
	kdfbuf[pos++] = 0;
	kdfbuf[pos++] = (uint8_t)(L >> 8);
	kdfbuf[pos++] = (uint8_t)L;

	bzero(&mech, sizeof (mech));
	if ((rc = smb2_hmac_getmech(&mech)) != 0)
		return (rc);

	smb2_sign_init_hmac_param(&mech, &param, keylen);

	rc = smb2_mac_raw(&mech,
	    ssn_key, ssn_keylen,
	    kdfbuf, pos,
	    outbuf, keylen);

	return (rc);
}
