/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"
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

int ldap_sasl_cram_md5_bind_s(
	LDAP *ld,
	char *dn,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls ) 
{
	int res;
	struct berval *challenge = NULL;
	struct berval resp;
	unsigned char digest[16];
	char *theHDigest;
	
	if (dn == NULL){
		return (LDAP_PARAM_ERROR);
	}

	bzero(digest, sizeof (digest));
	
	if ((res = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_CRAM_MD5, NULL, serverctrls, clientctrls, &challenge))
		!= LDAP_SASL_BIND_IN_PROGRESS){
		return (res);
	}
	if (challenge == NULL){
		return (LDAP_PARAM_ERROR);
	}
	
	LDAPDebug (LDAP_DEBUG_TRACE, "SASL challenge: %s\n", challenge->bv_val, 0, 0);
	
	hmac_md5((unsigned char *)challenge->bv_val, challenge->bv_len, 
					 (unsigned char *)cred->bv_val, cred->bv_len,  digest);
	ber_bvfree(challenge);
	challenge = NULL;
	
	theHDigest = hexa_print(digest, 16);
	if (theHDigest == NULL){
		return (LDAP_NO_MEMORY);
	}

	resp.bv_len = (strlen(dn) + 32 + 1);
	if ((resp.bv_val = (char *)malloc(resp.bv_len+1)) == NULL) {
		return(LDAP_NO_MEMORY);
	}
	
	sprintf(resp.bv_val, "%s %s", dn, theHDigest);
	free(theHDigest);

	LDAPDebug (LDAP_DEBUG_TRACE, "SASL response: %s\n", resp.bv_val, 0, 0);
	res = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_CRAM_MD5, &resp, serverctrls, clientctrls, &challenge);

	free(resp.bv_val);
	return (res);
}
