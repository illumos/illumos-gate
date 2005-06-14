/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  md5crypt - MD5 based authentication routines
 */

#include "ntp_types.h"
#include "ntp_string.h"
#include <md5.h>
#include "ntp_stdlib.h"

extern u_int32 cache_keyid;
extern char *cache_key;
extern int cache_keylen;

/*
 * Stat counters, imported from data base module
 */
extern u_int32 authencryptions;
extern u_int32 authdecryptions;
extern u_int32 authkeyuncached;
extern u_int32 authnokey;

/*
 * For our purposes an NTP packet looks like:
 *
 *	a variable amount of encrypted data, multiple of 8 bytes, followed by:
 *	NOCRYPT_OCTETS worth of unencrypted data, followed by:
 *	BLOCK_OCTETS worth of ciphered checksum.
 */ 
#define	NOCRYPT_OCTETS	4
#define	BLOCK_OCTETS	16

#define	NOCRYPT_int32S	((NOCRYPT_OCTETS)/sizeof(u_int32))
#define	BLOCK_int32S	((BLOCK_OCTETS)/sizeof(u_int32))

int
MD5authdecrypt(keyno, pkt, length)
    u_int32 keyno;
    const u_int32 *pkt;
    int length;		/* length of variable data in octets */
{
    MD5_CTX ctx;
#if defined(__NetBSD__) || defined(SYS_SOLARIS)
    unsigned char hash[16];
#endif

    authdecryptions++;

    if (keyno != cache_keyid) {
	authkeyuncached++;
	if (!authhavekey(keyno))
	    return 0;
    }

    MD5Init(&ctx);
#if defined(__NetBSD__) || defined(SYS_SOLARIS)
    MD5Update(&ctx, (unsigned char *)cache_key, cache_keylen);
    MD5Update(&ctx, (unsigned char *)pkt, length);
    MD5Final(hash, &ctx);
#else
    MD5Update(&ctx, (unsigned const char *)cache_key, cache_keylen);
    MD5Update(&ctx, (unsigned const char *)pkt, length);
    MD5Final(&ctx);
#endif

    return (!memcmp(
#if defined(__NetBSD__) || defined(SYS_SOLARIS)
		    (const char *) hash,
#else
		    (const char *) ctx.digest,
#endif
		    (const char *)pkt + length + 4,
		    BLOCK_OCTETS));
}
