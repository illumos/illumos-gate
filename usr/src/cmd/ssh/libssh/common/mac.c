/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
RCSID("$OpenBSD: mac.c,v 1.5 2002/05/16 22:02:50 markus Exp $");

#include <openssl/hmac.h>

#include "xmalloc.h"
#include "getput.h"
#include "log.h"
#include "cipher.h"
#include "kex.h"
#include "mac.h"
#include "misc.h"

#define SSH_EVP		1	/* OpenSSL EVP-based MAC */

struct {
	char		*name;
	int		type;
	const EVP_MD *	(*mdfunc)(void);
	int		truncatebits;	/* truncate digest if != 0 */
	int		key_len;	/* will be used if we have UMAC */
} macs[] = {
	{ "hmac-sha1",			SSH_EVP, EVP_sha1,	 0, -1 },
	{ "hmac-sha1-96",		SSH_EVP, EVP_sha1,	96, -1 },
	{ "hmac-md5",			SSH_EVP, EVP_md5,	 0, -1 },
	{ "hmac-md5-96",		SSH_EVP, EVP_md5,	96, -1 },
#ifdef SOLARIS_SSH_ENABLE_RIPEMD160
	{ "hmac-ripemd160",		SSH_EVP, EVP_ripemd160,  0, -1 },
	{ "hmac-ripemd160@openssh.com",	SSH_EVP, EVP_ripemd160,  0, -1 },
#endif /* SOLARIS_SSH_ENABLE_RIPEMD160 */
	{ NULL,				0,	 NULL,		 0, -1 }
};

static void
mac_setup_by_id(Mac *mac, int which)
{
	int evp_len;
	mac->type = macs[which].type;
	if (mac->type == SSH_EVP) {
		mac->evp_md = (*macs[which].mdfunc)();
		if ((evp_len = EVP_MD_size(mac->evp_md)) <= 0)
			fatal("mac %s len %d", mac->name, evp_len);
		mac->key_len = mac->mac_len = (u_int)evp_len;
	} else
		fatal("wrong MAC type (%d)", mac->type);
	if (macs[which].truncatebits != 0)
		mac->mac_len = macs[which].truncatebits / 8;
}

int
mac_setup(Mac *mac, char *name)
{
	int i;

	for (i = 0; macs[i].name; i++) {
		if (strcmp(name, macs[i].name) == 0) {
			if (mac != NULL)
				mac_setup_by_id(mac, i);
			debug2("mac_setup: found %s", name);
			return (0);
		}
	}
	debug2("mac_setup: unknown %s", name);
	return (-1);
}

int
mac_init(Mac *mac)
{
	if (mac->key == NULL)
		fatal("mac_init: no key");
	switch (mac->type) {
	case SSH_EVP:
		if (mac->evp_md == NULL)
			return -1;
		HMAC_Init(&mac->evp_ctx, mac->key, mac->key_len, mac->evp_md);
		return 0;
	default:
		return -1;
	}
}

u_char *
mac_compute(Mac *mac, u_int32_t seqno, u_char *data, int datalen)
{
	static u_char m[EVP_MAX_MD_SIZE];
	u_char b[4];

	if (mac->mac_len > sizeof(m))
		fatal("mac_compute: mac too long %u %lu",
		    mac->mac_len, (u_long)sizeof(m));

	switch (mac->type) {
	case SSH_EVP:
		put_u32(b, seqno);
		/* reset HMAC context */
		HMAC_Init(&mac->evp_ctx, NULL, 0, NULL);
		HMAC_Update(&mac->evp_ctx, b, sizeof(b));
		HMAC_Update(&mac->evp_ctx, data, datalen);
		HMAC_Final(&mac->evp_ctx, m, NULL);
		break;
	default:
		fatal("mac_compute: unknown MAC type");
	}

	return (m);
}

void
mac_clear(Mac *mac)
{
	if (mac->evp_md != NULL)
		HMAC_cleanup(&mac->evp_ctx);
	mac->evp_md = NULL;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
int
mac_valid(const char *names)
{
	char *maclist, *cp, *p;

	if (names == NULL || strcmp(names, "") == 0)
		return (0);
	maclist = cp = xstrdup(names);
	for ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		if (mac_setup(NULL, p) < 0) {
			debug("bad mac %s [%s]", p, names);
			xfree(maclist);
			return (0);
		} else {
			debug3("mac ok: %s [%s]", p, names);
		}
	}
	debug3("macs ok: [%s]", names);
	xfree(maclist);
	return (1);
}
