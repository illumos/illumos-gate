/*
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <strings.h>
#include "sec.h"

/* text is the challenge, key is the password, digest is an allocated
   buffer (min 16 chars) which will contain the resulting digest */
void hmac_md5(unsigned char *text, int text_len, unsigned char *key,
	int key_len, unsigned char *digest)
{
	MD5_CTX context;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	unsigned char tk[16];
	int i;

	if (key_len > 64){
		MD5_CTX tctx;

		(void) MD5Init(&tctx);
		(void) MD5Update(&tctx, key, key_len);
		(void) MD5Final(tk, &tctx);
		key = tk;
		key_len = 16;
	}

	bzero(k_ipad, sizeof (k_ipad));
	bzero(k_opad, sizeof (k_opad));
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);

	for (i=0; i<64; i++){
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* Perform inner MD5 */
	(void) MD5Init(&context);
	(void) MD5Update(&context, k_ipad, 64);
	(void) MD5Update(&context, text, text_len);
	(void) MD5Final(digest, &context);

	/* Perform outer MD5 */
	(void) MD5Init(&context);
	(void) MD5Update(&context, k_opad, 64);
	(void) MD5Update(&context, digest, 16);

	(void) MD5Final(digest, &context);

	return;
}
