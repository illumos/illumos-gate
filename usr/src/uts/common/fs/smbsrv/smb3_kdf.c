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
 * Copyright 2020 RackTop Systems, Inc.
 */

#include <smbsrv/smb_kcrypt.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * Derive SMB3 key as described in [MS-SMB2] 3.1.4.2
 * and [NIST SP800-108]
 *
 * r = 32, L = 128, PRF = HMAC-SHA256, key = (session key)
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

/*
 * SMB3KDF(Ki, Label, Context)
 * counter || Label || 0x00 || Context || L
 */
int
smb3_kdf(uint8_t *outbuf,
    uint8_t *key, size_t key_len,
    uint8_t *label, size_t label_len,
    uint8_t *context, size_t context_len)
{
	static uint8_t L[4] = { 0, 0, 0, 0x80 };
	uint8_t digest32[SHA256_DIGEST_LENGTH];
	/* Maximum length of kdf input is 89 for Encription/Decryption key */
	uint8_t kdfbuf[89] = { 0, 0, 0, 1 };	/* initialized by counter */
	smb_crypto_mech_t mech;
	smb_sign_ctx_t hctx = 0;
	int pos = 4;	/* skip counter */
	int rc;

	bcopy(label, &kdfbuf[pos], label_len);
	pos += label_len;

	kdfbuf[pos] = 0;
	pos++;

	bcopy(context, &kdfbuf[pos], context_len);
	pos += context_len;

	bcopy(L, &kdfbuf[pos], 4);
	pos += 4;

	bzero(&mech, sizeof (mech));
	if ((rc = smb2_hmac_getmech(&mech)) != 0)
		return (rc);

	/* Limit the SessionKey input to its maximum size (16 bytes) */
	rc = smb2_hmac_init(&hctx, &mech, key, MIN(key_len, SMB2_KEYLEN));
	if (rc != 0)
		return (rc);

	if ((rc = smb2_hmac_update(hctx, kdfbuf, pos)) != 0)
		return (rc);

	if ((rc = smb2_hmac_final(hctx, digest32)) != 0)
		return (rc);

	/* Output is first 16 bytes of digest. */
	bcopy(digest32, outbuf, SMB3_KEYLEN);
	return (0);
}
