/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * authencrypt - compute and encrypt the mac field in an NTP packet
 */
#include "ntp_stdlib.h"

/*
 * For our purposes an NTP packet looks like:
 *
 *	a variable amount of encrypted data, multiple of 8 bytes, followed by:
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
extern u_int32 DEScache_ekeys[];	/* cached decryption keys */
extern u_int32 DESzeroekeys[];	/* zero key decryption keys */

/*
 * Stat counters from the database module
 */
extern u_int32 authencryptions;
extern u_int32 authkeyuncached;
extern u_int32 authnokey;

int
DESauthencrypt(keyno, pkt, length)
	u_int32 keyno;
	u_int32 *pkt;
	int length;	/* length of encrypted portion of packet */
{
	register u_int32 *pd;
	register int i;
	register u_char *keys;
	register int len;
	u_int32 work[2];

	authencryptions++;

	if (keyno == 0) {
		keys = (u_char *)DESzeroekeys;
	} else {
		if (keyno != cache_keyid) {
			authkeyuncached++;
			if (!authhavekey(keyno)) {
				authnokey++;
				return 0;
			}
		}
		keys = (u_char *)DEScache_ekeys;
	}

	/*
	 * Do the encryption.  Work our way forward in the packet, eight
	 * bytes at a time, encrypting as we go.  Note that the byte order
	 * issues are handled by the DES routine itself
	 */
	pd = pkt;
	work[0] = work[1] = 0;
	len = length / sizeof(u_int32);

	for (i = (len/2); i > 0; i--) {
		work[0] ^= *pd++;
		work[1] ^= *pd++;
		DESauth_des(work, keys);
	}

	if (len & 0x1) {
		work[0] ^= *pd++;
		DESauth_des(work, keys);
	}

	/*
	 * Space past the keyid and stick the result back in the mac field
	 */
	pd += NOCRYPT_int32S;
	*pd++ = work[0];
	*pd = work[1];

	return 4 + BLOCK_OCTETS;	/* return size of key and MAC  */
}
