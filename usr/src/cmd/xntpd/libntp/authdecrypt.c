/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * authdecrypt - routine to decrypt a packet to see if this guy knows our key.
 */
#include "ntp_stdlib.h"
 
/*
 * For our purposes an NTP packet looks like:
 *
 *	a variable amount of unencrypted data, multiple of 8 bytes, followed by:
 *	NOCRYPT_OCTETS worth of unencrypted data, followed by:
 *	BLOCK_OCTETS worth of ciphered checksum.
 */ 
#define	NOCRYPT_OCTETS	4
#define	BLOCK_OCTETS	8

#define	NOCRYPT_int32S	((NOCRYPT_OCTETS)/sizeof(u_int32))
#define	BLOCK_int32S	((BLOCK_OCTETS)/sizeof(u_int32))

/*
 * Imported from the key data base module
 */
extern u_int32 cache_keyid;	/* cached key ID */
extern u_int32 DEScache_dkeys[];	/* cached decryption keys */
extern u_int32 DESzerodkeys[];	/* zero key decryption keys */

/*
 * Stat counters, imported from data base module
 */
extern u_int32 authdecryptions;
extern u_int32 authkeyuncached;

int
DESauthdecrypt(keyno, pkt, length)
	u_int32 keyno;
	const u_int32 *pkt;
	int length;	/* length of variable data in octets */
{
	register const u_int32 *pd;
	register int i;
	register u_char *keys;
	register int longlen;
	u_int32 work[2];

	authdecryptions++;
	
	if (keyno == 0)
		keys = (u_char *)DESzerodkeys;
	else {
		if (keyno != cache_keyid) {
			authkeyuncached++;
			if (!authhavekey(keyno))
				return 0;
		}
		keys = (u_char *)DEScache_dkeys;
	}

	/*
	 * Get encryption block data in host byte order and decrypt it.
	 */
	longlen = length / sizeof(u_int32);
	pd = pkt + longlen;		/* points at NOCRYPT area */
	work[0] = *(pd + NOCRYPT_int32S);
	work[1] = *(pd + NOCRYPT_int32S + 1);

	if (longlen & 0x1) {
		DESauth_des(work, keys);
		work[0] ^= *(--pd);
	}

	for (i = longlen/2; i > 0; i--) {
		DESauth_des(work, keys);
		work[1] ^= *(--pd);
		work[0] ^= *(--pd);
	}

	/*
	 * Success if the encryption data is zero
	 */
	if ((work[0] == 0) && (work[1] == 0))
		return 1;
	return 0;
}
