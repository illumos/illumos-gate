/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/param.h>
#include <sys/int_limits.h>
#include <sys/byteorder.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <netinet/in.h>
#include "sfxge.h"
#include "efx.h"

/*
 * The largest amount of the data which the hash may be calculated over
 * is a 4-tuple of source/destination IPv6 addresses (2 x 16 bytes)
 * and source/destination TCP port numbers (2 x 2 bytes), adding up to 40 bytes
 */
#define	SFXGE_TOEPLITZ_IN_MAX \
	(2 * (sizeof (struct in6_addr) + sizeof (in_port_t)))
#define	SFXGE_TOEPLITZ_CACHE_SIZE (SFXGE_TOEPLITZ_IN_MAX * (UINT8_MAX + 1))

static uint32_t
toeplitz_hash(const uint32_t *cache, const uint8_t *input,
    unsigned pos, unsigned datalen)
{
	uint32_t hash = 0;
	for (; datalen != 0; datalen--, pos++, input++) {
		hash ^= cache[pos * (UINT8_MAX + 1) + *input];
	}

	return (hash);
}

uint32_t
sfxge_toeplitz_hash(sfxge_t *sp, unsigned int addr_size,
    uint8_t *src_addr, uint16_t src_port, uint8_t *dst_addr, uint16_t dst_port)
{
	uint32_t hash = 0;
	unsigned pos = 0;

	hash ^= toeplitz_hash(sp->s_toeplitz_cache, src_addr, pos, addr_size);
	pos += addr_size;
	hash ^= toeplitz_hash(sp->s_toeplitz_cache, dst_addr, pos, addr_size);
	pos += addr_size;
	if (src_port != 0 || dst_port != 0) {
		hash ^= toeplitz_hash(sp->s_toeplitz_cache,
		    (const uint8_t *)&src_port, pos, sizeof (src_port));
		pos += sizeof (src_port);
		hash ^= toeplitz_hash(sp->s_toeplitz_cache,
		    (const uint8_t *)&dst_port, pos, sizeof (dst_port));
	}
	return (hash);
}

/*
 * The algorithm to calculate RSS Toeplitz hash is essentially as follows:
 * - Regard a Toeplitz key and an input as bit strings, with the
 * most significant bit of the first byte being the first bit
 * - Let's have a 32-bit window sliding over the Toeplitz key bit by bit
 * - Let the initial value of the hash be zero
 * - Then for every bit in the input that is set to 1, XOR the value of the
 *   window at a given bit position into the resulting hash
 *
 * First we note that since XOR is commutative and associative, the
 * resulting hash is just a XOR of subhashes for every input bit:
 *        H = H_0 XOR H_1 XOR ... XOR H_n               (1)
 * Then we note that every H_i is only dependent on the value of i and
 * the value of i'th bit of input, but not on any preceding or following
 * input bits.
 * Then we note that (1) holds also for any bit sequences,
 * e.g. for bytes of input:
 *       H = H_0_7 XOR H_8_15 XOR ... XOR H_(n-7)_n     (2)
 * and every
 *       H_i_j = H_i XOR H_(i+1) ... XOR H_j.           (3)
 *
 * It naturally follows than H_i_(i+7) only depends on the value of the byte
 * and the position of the byte in the input.
 * Therefore we may pre-calculate the value of each byte sub-hash H_i_(i+7)
 * for each possible byte value and each possible byte input position, and
 * then just assemble the hash of the packet byte-by-byte instead of
 * bit-by-bit.
 *
 * The amount of memory required for such a cache is not prohibitive:
 * - we have at most 36 bytes of input, each holding 256 possible values
 * - and the hash is 32-bit wide
 * - hence, we need only 36 * 256 * 4 = 36kBytes of cache.
 *
 * The performance gain, at least on synthetic benchmarks, is significant:
 * cache lookup is about 15 times faster than direct hash calculation
 */
const uint32_t *
toeplitz_cache_init(const uint8_t *key)
{
	uint32_t *cache = kmem_alloc(SFXGE_TOEPLITZ_CACHE_SIZE *
	    sizeof (uint32_t), KM_SLEEP);
	unsigned i;

	for (i = 0; i < SFXGE_TOEPLITZ_IN_MAX; i++, key++) {
		uint32_t key_bits[NBBY] = { 0 };
		unsigned j;
		unsigned mask;
		unsigned byte;

#if defined(BE_IN32)
		key_bits[0] = BE_IN32(key);
#else
		key_bits[0] = BE_32(*(uint32_t *)key);
#endif
		for (j = 1, mask = 1 << (NBBY - 1); j < NBBY; j++, mask >>= 1) {
			key_bits[j] = key_bits[j - 1] << 1;
			if ((key[sizeof (uint32_t)] & mask) != 0)
				key_bits[j] |= 1;
		}

		for (byte = 0; byte <= UINT8_MAX; byte++) {
			uint32_t res = 0;
			for (j = 0, mask = 1 << (NBBY - 1);
			    j < NBBY;
			    j++, mask >>= 1) {
				if (byte & mask)
					res ^= key_bits[j];
			}
			cache[i * (UINT8_MAX + 1) + byte] = res;
		}
	}
	return (cache);
}


int
sfxge_toeplitz_hash_init(sfxge_t *sp)
{
	int rc;
	uint8_t toeplitz_key[SFXGE_TOEPLITZ_KEY_LEN];

	(void) random_get_pseudo_bytes(toeplitz_key, sizeof (toeplitz_key));

	if ((rc = efx_rx_scale_mode_set(sp->s_enp, EFX_RX_HASHALG_TOEPLITZ,
	    (1 << EFX_RX_HASH_IPV4) | (1 << EFX_RX_HASH_TCPIPV4) |
	    (1 << EFX_RX_HASH_IPV6) | (1 << EFX_RX_HASH_TCPIPV6), B_TRUE)) != 0)
		return (rc);

	if ((rc = efx_rx_scale_key_set(sp->s_enp, toeplitz_key,
	    sizeof (toeplitz_key))) != 0)
		return (rc);

	sp->s_toeplitz_cache = toeplitz_cache_init(toeplitz_key);

	return (0);
}

void
sfxge_toeplitz_hash_fini(sfxge_t *sp)
{
	if (sp->s_toeplitz_cache != NULL) {
		kmem_free((void *)sp->s_toeplitz_cache,
		    SFXGE_TOEPLITZ_CACHE_SIZE);
		sp->s_toeplitz_cache = NULL;
	}
}
