/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * auth12crypt.c - routines to support two stage NTP encryption
 */
#include "ntp_stdlib.h"

/*
 * For our purposes an NTP packet looks like:
 *
 *	a variable amount of encrypted data, multiple of 8 bytes, which
 *		is encrypted in pass 1, followed by:
 *	an 8 byte chunk of data which is encrypted in pass 2
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
extern u_int32 DEScache_ekeys[]; /* cached decryption keys */
extern u_int32 DESzeroekeys[];	/* zero key decryption keys */

/*
 * Stat counters, from the database module
 */
extern u_int32 authencryptions;
extern u_int32 authkeyuncached;
extern u_int32 authnokey;


/*
 * auth1crypt - do the first stage of a two stage encryption
 */
void
DESauth1crypt(keyno, pkt, length)
	u_int32 keyno;
	u_int32 *pkt;
	int length;	/* length of all encrypted data */
{
	register u_int32 *pd;
	register int i;
	register u_char *keys;
	u_int32 work[2];

	authencryptions++;

	if (keyno == 0) {
		keys = (u_char *)DESzeroekeys;
	} else {
		if (keyno != cache_keyid) {
			authkeyuncached++;
			if (!authhavekey(keyno)) {
				authnokey++;
				return;
			}
		}
		keys = (u_char *)DEScache_ekeys;
	}

	/*
	 * Do the first five encryptions.  Stick the intermediate result
	 * in the mac field.  The sixth encryption must wait until the
	 * caller freezes a transmit time stamp, and will be done in stage 2.
	 */
	pd = pkt;
	work[0] = work[1] = 0;

	for (i = (length/BLOCK_OCTETS - 1); i > 0; i--) {
		work[0] ^= *pd++;
		work[1] ^= *pd++;
		DESauth_des(work, keys);
	}

	/*
	 * Space to the end of the packet and stick the intermediate
	 * result in the mac field.
	 */
	pd += BLOCK_int32S + NOCRYPT_int32S;
	*pd++ = work[0];
	*pd = work[1];
}


/*
 * auth2crypt - do the second stage of a two stage encryption
 */
int
DESauth2crypt(keyno, pkt, length)
	u_int32 keyno;
	u_int32 *pkt;
	int length;	/* total length of encrypted area */
{
	register u_int32 *pd;
	register u_char *keys;

	/*
	 * Skip the key check.  The call to the first stage should
	 * have got it.
	 */
	if (keyno == 0)
		keys = (u_char *)DESzeroekeys;
	else
		keys = (u_char *)DEScache_ekeys;

	/*
	 * The mac currently should hold the results of the first `n'
	 * encryptions.  We xor in the last block in data section and
	 * do the final encryption in place.
	 *
	 * Get a pointer to the MAC block.  XOR in the last two words of
	 * the data area. Call the encryption routine.
	 */
	pd = pkt + (length/sizeof(u_int32)) + NOCRYPT_int32S;

	*pd ^= *(pd - NOCRYPT_int32S - 2);
	*(pd + 1) ^= *(pd - NOCRYPT_int32S - 1);
	DESauth_des(pd, keys);

	return  4 + 8;		/* return size of key number and MAC */
}
