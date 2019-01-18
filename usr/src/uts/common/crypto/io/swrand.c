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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Software based random number provider for the Kernel Cryptographic
 * Framework (KCF). This provider periodically collects unpredictable input
 * from external sources and processes it into a pool of entropy (randomness)
 * in order to satisfy requests for random bits from kCF. It implements
 * software-based mixing, extraction, and generation algorithms.
 *
 * A history note: The software-based algorithms in this file used to be
 * part of the /dev/random driver.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/seg_kmem.h>
#include <vm/hat.h>
#include <sys/systm.h>
#include <sys/memlist.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/random.h>
#include <sys/ddi.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/mem_config.h>
#include <sys/time.h>
#include <sys/crypto/spi.h>
#include <sys/sha1.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/hold_page.h>
#include <rng/fips_random.h>

#define	RNDPOOLSIZE		1024	/* Pool size in bytes */
#define	HASHBUFSIZE		64	/* Buffer size used for pool mixing */
#define	MAXMEMBLOCKS		16384	/* Number of memory blocks to scan */
#define	MEMBLOCKSIZE		4096	/* Size of memory block to read */
#define	MINEXTRACTBITS		160	/* Min entropy level for extraction */
#define	TIMEOUT_INTERVAL	5	/* Periodic mixing interval in secs */

/* Hash-algo generic definitions. For now, they are SHA1's. */
#define	HASHSIZE		20
#define	HASH_CTX		SHA1_CTX
#define	HashInit(ctx)		SHA1Init((ctx))
#define	HashUpdate(ctx, p, s)	SHA1Update((ctx), (p), (s))
#define	HashFinal(d, ctx)	SHA1Final((d), (ctx))

/* Physical memory entropy source */
typedef struct physmem_entsrc_s {
	uint8_t *parity;		/* parity bit vector */
	caddr_t pmbuf;			/* buffer for memory block */
	uint32_t nblocks;		/* number of  memory blocks */
	int entperblock;		/* entropy bits per block read */
	hrtime_t last_diff;		/* previous time to process a block */
	hrtime_t last_delta;		/* previous time delta */
	hrtime_t last_delta2;		/* previous 2nd order time delta */
} physmem_entsrc_t;

static uint32_t srndpool[RNDPOOLSIZE/4];	/* Pool of random bits */
static uint32_t buffer[RNDPOOLSIZE/4];	/* entropy mixed in later */
static int buffer_bytes;		/* bytes written to buffer */
static uint32_t entropy_bits;		/* pool's current amount of entropy */
static kmutex_t srndpool_lock;		/* protects r/w accesses to the pool, */
					/* and the global variables */
static kmutex_t buffer_lock;		/* protects r/w accesses to buffer */
static kcondvar_t srndpool_read_cv;	/* serializes poll/read syscalls */
static int pindex;			/* Global index for adding/extracting */
					/* from the pool */
static int bstart, bindex;		/* Global vars for adding/extracting */
					/* from the buffer */
static uint8_t leftover[HASHSIZE];	/* leftover output */
static uint32_t	swrand_XKEY[6];		/* one extra word for getentropy */
static int leftover_bytes;		/* leftover length */
static uint32_t previous_bytes[HASHSIZE/BYTES_IN_WORD];	/* prev random bytes */

static physmem_entsrc_t entsrc;		/* Physical mem as an entropy source */
static timeout_id_t rnd_timeout_id;
static int snum_waiters;
static crypto_kcf_provider_handle_t swrand_prov_handle = 0;
swrand_stats_t swrand_stats;

static int physmem_ent_init(physmem_entsrc_t *);
static void physmem_ent_fini(physmem_entsrc_t *);
static void physmem_ent_gen(physmem_entsrc_t *);
static int physmem_parity_update(uint8_t *, uint32_t, int);
static void physmem_count_blocks();
static void rnd_dr_callback_post_add(void *, pgcnt_t);
static int rnd_dr_callback_pre_del(void *, pgcnt_t);
static void rnd_dr_callback_post_del(void *, pgcnt_t, int);
static void rnd_handler(void *arg);
static void swrand_init();
static void swrand_schedule_timeout(void);
static int swrand_get_entropy(uint8_t *ptr, size_t len, boolean_t);
static void swrand_add_entropy(uint8_t *ptr, size_t len, uint16_t entropy_est);
static void swrand_add_entropy_later(uint8_t *ptr, size_t len);

/* Dynamic Reconfiguration related declarations */
kphysm_setup_vector_t rnd_dr_callback_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	rnd_dr_callback_post_add,
	rnd_dr_callback_pre_del,
	rnd_dr_callback_post_del
};

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"Kernel Random number Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */
static void swrand_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t swrand_control_ops = {
	swrand_provider_status
};

static int swrand_seed_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, uint_t, uint32_t, crypto_req_handle_t);
static int swrand_generate_random(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t swrand_random_number_ops = {
	swrand_seed_random,
	swrand_generate_random
};

static crypto_ops_t swrand_crypto_ops = {
	&swrand_control_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&swrand_random_number_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

static crypto_provider_info_t swrand_prov_info = {
	CRYPTO_SPI_VERSION_4,
	"Kernel Random Number Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&swrand_crypto_ops,
	0,
	NULL
};

int
_init(void)
{
	int ret;
	hrtime_t ts;
	time_t now;

	mutex_init(&srndpool_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&buffer_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&srndpool_read_cv, NULL, CV_DEFAULT, NULL);
	entropy_bits = 0;
	pindex = 0;
	bindex = 0;
	bstart = 0;
	snum_waiters = 0;
	leftover_bytes = 0;
	buffer_bytes = 0;

	/*
	 * Initialize the pool using
	 * . 2 unpredictable times: high resolution time since the boot-time,
	 *   and the current time-of-the day.
	 * . The initial physical memory state.
	 */
	ts = gethrtime();
	swrand_add_entropy((uint8_t *)&ts, sizeof (ts), 0);

	(void) drv_getparm(TIME, &now);
	swrand_add_entropy((uint8_t *)&now, sizeof (now), 0);

	ret = kphysm_setup_func_register(&rnd_dr_callback_vec, NULL);
	ASSERT(ret == 0);

	if (physmem_ent_init(&entsrc) != 0) {
		ret = ENOMEM;
		goto exit1;
	}

	if ((ret = mod_install(&modlinkage)) != 0)
		goto exit2;

	/* Schedule periodic mixing of the pool. */
	mutex_enter(&srndpool_lock);
	swrand_schedule_timeout();
	mutex_exit(&srndpool_lock);
	(void) swrand_get_entropy((uint8_t *)swrand_XKEY, HASHSIZE, B_TRUE);
	bcopy(swrand_XKEY, previous_bytes, HASHSIZE);

	/* Register with KCF. If the registration fails, return error. */
	if (crypto_register_provider(&swrand_prov_info, &swrand_prov_handle)) {
		(void) mod_remove(&modlinkage);
		ret = EACCES;
		goto exit2;
	}

	return (0);

exit2:
	physmem_ent_fini(&entsrc);
exit1:
	mutex_destroy(&srndpool_lock);
	mutex_destroy(&buffer_lock);
	cv_destroy(&srndpool_read_cv);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Control entry points.
 */
/* ARGSUSED */
static void
swrand_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * Random number entry points.
 */
/* ARGSUSED */
static int
swrand_seed_random(crypto_provider_handle_t provider, crypto_session_id_t sid,
    uchar_t *buf, size_t len, uint_t entropy_est, uint32_t flags,
    crypto_req_handle_t req)
{
	/* The entropy estimate is always 0 in this path */
	if (flags & CRYPTO_SEED_NOW)
		swrand_add_entropy(buf, len, 0);
	else
		swrand_add_entropy_later(buf, len);
	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
swrand_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t sid, uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	if (crypto_kmflag(req) == KM_NOSLEEP)
		(void) swrand_get_entropy(buf, len, B_TRUE);
	else
		(void) swrand_get_entropy(buf, len, B_FALSE);

	return (CRYPTO_SUCCESS);
}

/*
 * Extraction of entropy from the pool.
 *
 * Returns "len" random bytes in *ptr.
 * Try to gather some more entropy by calling physmem_ent_gen() when less than
 * MINEXTRACTBITS are present in the pool.
 * Will block if not enough entropy was available and the call is blocking.
 */
static int
swrand_get_entropy(uint8_t *ptr, size_t len, boolean_t nonblock)
{
	int i, bytes;
	HASH_CTX hashctx;
	uint8_t digest[HASHSIZE], *pool;
	uint32_t tempout[HASHSIZE/BYTES_IN_WORD];
	int size;

	mutex_enter(&srndpool_lock);
	if (leftover_bytes > 0) {
		bytes = min(len, leftover_bytes);
		bcopy(leftover, ptr, bytes);
		len -= bytes;
		ptr += bytes;
		leftover_bytes -= bytes;
		if (leftover_bytes > 0)
			ovbcopy(leftover+bytes, leftover, leftover_bytes);
	}

	while (len > 0) {
		/* Check if there is enough entropy */
		while (entropy_bits < MINEXTRACTBITS) {

			physmem_ent_gen(&entsrc);

			if (entropy_bits < MINEXTRACTBITS &&
			    nonblock == B_TRUE) {
				mutex_exit(&srndpool_lock);
				return (EAGAIN);
			}

			if (entropy_bits < MINEXTRACTBITS) {
				ASSERT(nonblock == B_FALSE);
				snum_waiters++;
				if (cv_wait_sig(&srndpool_read_cv,
				    &srndpool_lock) == 0) {
					snum_waiters--;
					mutex_exit(&srndpool_lock);
					return (EINTR);
				}
				snum_waiters--;
			}
		}

		/* Figure out how many bytes to extract */
		bytes = min(HASHSIZE, len);
		bytes = min(bytes, CRYPTO_BITS2BYTES(entropy_bits));
		entropy_bits -= CRYPTO_BYTES2BITS(bytes);
		BUMP_SWRAND_STATS(ss_entOut, CRYPTO_BYTES2BITS(bytes));
		swrand_stats.ss_entEst = entropy_bits;

		/* Extract entropy by hashing pool content */
		HashInit(&hashctx);
		HashUpdate(&hashctx, (uint8_t *)srndpool, RNDPOOLSIZE);
		HashFinal(digest, &hashctx);

		/*
		 * Feed the digest back into the pool so next
		 * extraction produces different result
		 */
		pool = (uint8_t *)srndpool;
		for (i = 0; i < HASHSIZE; i++) {
			pool[pindex++] ^= digest[i];
			/* pindex modulo RNDPOOLSIZE */
			pindex &= (RNDPOOLSIZE - 1);
		}

		/* LINTED E_BAD_PTR_CAST_ALIGN */
		fips_random_inner(swrand_XKEY, tempout, (uint32_t *)digest);

		if (len >= HASHSIZE) {
			size = HASHSIZE;
		} else {
			size = min(bytes, HASHSIZE);
		}

		/*
		 * FIPS 140-2: Continuous RNG test - each generation
		 * of an n-bit block shall be compared with the previously
		 * generated block. Test shall fail if any two compared
		 * n-bit blocks are equal.
		 */
		for (i = 0; i < HASHSIZE/BYTES_IN_WORD; i++) {
			if (tempout[i] != previous_bytes[i])
				break;
		}

		if (i == HASHSIZE/BYTES_IN_WORD) {
			cmn_err(CE_WARN, "swrand: The value of 160-bit block "
			    "random bytes are same as the previous one.\n");
			/* discard random bytes and return error */
			return (EIO);
		}

		bcopy(tempout, previous_bytes, HASHSIZE);

		bcopy(tempout, ptr, size);
		if (len < HASHSIZE) {
			leftover_bytes = HASHSIZE - bytes;
			bcopy((uint8_t *)tempout + bytes, leftover,
			    leftover_bytes);
		}

		ptr += size;
		len -= size;
		BUMP_SWRAND_STATS(ss_bytesOut, size);
	}

	/* Zero out sensitive information */
	bzero(digest, HASHSIZE);
	bzero(tempout, HASHSIZE);
	mutex_exit(&srndpool_lock);
	return (0);
}

#define	SWRAND_ADD_BYTES(ptr, len, i, pool)		\
	ASSERT((ptr) != NULL && (len) > 0);		\
	BUMP_SWRAND_STATS(ss_bytesIn, (len));		\
	while ((len)--) {				\
		(pool)[(i)++] ^= *(ptr);		\
		(ptr)++;				\
		(i) &= (RNDPOOLSIZE - 1);		\
	}

/* Write some more user-provided entropy to the pool */
static void
swrand_add_bytes(uint8_t *ptr, size_t len)
{
	uint8_t *pool = (uint8_t *)srndpool;

	ASSERT(MUTEX_HELD(&srndpool_lock));
	SWRAND_ADD_BYTES(ptr, len, pindex, pool);
}

/*
 * Add bytes to buffer. Adding the buffer to the random pool
 * is deferred until the random pool is mixed.
 */
static void
swrand_add_bytes_later(uint8_t *ptr, size_t len)
{
	uint8_t *pool = (uint8_t *)buffer;

	ASSERT(MUTEX_HELD(&buffer_lock));
	SWRAND_ADD_BYTES(ptr, len, bindex, pool);
	buffer_bytes += len;
}

#undef SWRAND_ADD_BYTES

/* Mix the pool */
static void
swrand_mix_pool(uint16_t entropy_est)
{
	int i, j, k, start;
	HASH_CTX hashctx;
	uint8_t digest[HASHSIZE];
	uint8_t *pool = (uint8_t *)srndpool;
	uint8_t *bp = (uint8_t *)buffer;

	ASSERT(MUTEX_HELD(&srndpool_lock));

	/* add deferred bytes */
	mutex_enter(&buffer_lock);
	if (buffer_bytes > 0) {
		if (buffer_bytes >= RNDPOOLSIZE) {
			for (i = 0; i < RNDPOOLSIZE/4; i++) {
				srndpool[i] ^= buffer[i];
				buffer[i] = 0;
			}
			bstart = bindex = 0;
		} else {
			for (i = 0; i < buffer_bytes; i++) {
				pool[pindex++] ^= bp[bstart];
				bp[bstart++] = 0;
				pindex &= (RNDPOOLSIZE - 1);
				bstart &= (RNDPOOLSIZE - 1);
			}
			ASSERT(bstart == bindex);
		}
		buffer_bytes = 0;
	}
	mutex_exit(&buffer_lock);

	start = 0;
	for (i = 0; i < RNDPOOLSIZE/HASHSIZE + 1; i++) {
		HashInit(&hashctx);

		/* Hash a buffer centered on a block in the pool */
		if (start + HASHBUFSIZE <= RNDPOOLSIZE)
			HashUpdate(&hashctx, &pool[start], HASHBUFSIZE);
		else {
			HashUpdate(&hashctx, &pool[start],
			    RNDPOOLSIZE - start);
			HashUpdate(&hashctx, pool,
			    HASHBUFSIZE - RNDPOOLSIZE + start);
		}
		HashFinal(digest, &hashctx);

		/* XOR the hash result back into the block */
		k = (start + HASHSIZE) & (RNDPOOLSIZE - 1);
		for (j = 0; j < HASHSIZE; j++) {
			pool[k++] ^= digest[j];
			k &= (RNDPOOLSIZE - 1);
		}

		/* Slide the hash buffer and repeat with next block */
		start = (start + HASHSIZE) & (RNDPOOLSIZE - 1);
	}

	entropy_bits += entropy_est;
	if (entropy_bits > CRYPTO_BYTES2BITS(RNDPOOLSIZE))
		entropy_bits = CRYPTO_BYTES2BITS(RNDPOOLSIZE);

	swrand_stats.ss_entEst = entropy_bits;
	BUMP_SWRAND_STATS(ss_entIn, entropy_est);
}

static void
swrand_add_entropy_later(uint8_t *ptr, size_t len)
{
	mutex_enter(&buffer_lock);
	swrand_add_bytes_later(ptr, len);
	mutex_exit(&buffer_lock);
}

static void
swrand_add_entropy(uint8_t *ptr, size_t len, uint16_t entropy_est)
{
	mutex_enter(&srndpool_lock);
	swrand_add_bytes(ptr, len);
	swrand_mix_pool(entropy_est);
	mutex_exit(&srndpool_lock);
}

/*
 * The physmem_* routines below generate entropy by reading blocks of
 * physical memory.  Entropy is gathered in a couple of ways:
 *
 *  - By reading blocks of physical memory and detecting if changes
 *    occurred in the blocks read.
 *
 *  - By measuring the time it takes to load and hash a block of memory
 *    and computing the differences in the measured time.
 *
 * The first method was used in the CryptoRand implementation.  Physical
 * memory is divided into blocks of fixed size.  A block of memory is
 * chosen from the possible blocks and hashed to produce a digest.  This
 * digest is then mixed into the pool.  A single bit from the digest is
 * used as a parity bit or "checksum" and compared against the previous
 * "checksum" computed for the block.  If the single-bit checksum has not
 * changed, no entropy is credited to the pool.  If there is a change,
 * then the assumption is that at least one bit in the block has changed.
 * The possible locations within the memory block of where the bit change
 * occurred is used as a measure of entropy.  For example, if a block
 * size of 4096 bytes is used, about log_2(4096*8)=15 bits worth of
 * entropy is available.  Because the single-bit checksum will miss half
 * of the changes, the amount of entropy credited to the pool is doubled
 * when a change is detected.  With a 4096 byte block size, a block
 * change will add a total of 30 bits of entropy to the pool.
 *
 * The second method measures the amount of time it takes to read and
 * hash a physical memory block (as described above).  The time measured
 * can vary depending on system load, scheduling and other factors.
 * Differences between consecutive measurements are computed to come up
 * with an entropy estimate.  The first, second, and third order delta is
 * calculated to determine the minimum delta value.  The number of bits
 * present in this minimum delta value is the entropy estimate.  This
 * entropy estimation technique using time deltas is similar to that used
 * in /dev/random implementations from Linux/BSD.
 */

static int
physmem_ent_init(physmem_entsrc_t *entsrc)
{
	uint8_t *ptr;
	int i;

	bzero(entsrc, sizeof (*entsrc));

	/*
	 * The maximum entropy amount in bits per block of memory read is
	 * log_2(MEMBLOCKSIZE * 8);
	 */
	i = CRYPTO_BYTES2BITS(MEMBLOCKSIZE);
	while (i >>= 1)
		entsrc->entperblock++;

	/* Initialize entsrc->nblocks */
	physmem_count_blocks();

	if (entsrc->nblocks == 0) {
		cmn_err(CE_WARN, "no memory blocks to scan!");
		return (-1);
	}

	/* Allocate space for the parity vector and memory page */
	entsrc->parity = kmem_alloc(howmany(entsrc->nblocks, 8),
	    KM_SLEEP);
	entsrc->pmbuf = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);


	/* Initialize parity vector with bits from the pool */
	i = howmany(entsrc->nblocks, 8);
	ptr = entsrc->parity;
	while (i > 0) {
		if (i > RNDPOOLSIZE) {
			bcopy(srndpool, ptr, RNDPOOLSIZE);
			mutex_enter(&srndpool_lock);
			swrand_mix_pool(0);
			mutex_exit(&srndpool_lock);
			ptr += RNDPOOLSIZE;
			i -= RNDPOOLSIZE;
		} else {
			bcopy(srndpool, ptr, i);
			break;
		}
	}

	/* Generate some entropy to further initialize the pool */
	mutex_enter(&srndpool_lock);
	physmem_ent_gen(entsrc);
	entropy_bits = 0;
	mutex_exit(&srndpool_lock);

	return (0);
}

static void
physmem_ent_fini(physmem_entsrc_t *entsrc)
{
	if (entsrc->pmbuf != NULL)
		vmem_free(heap_arena, entsrc->pmbuf, PAGESIZE);
	if (entsrc->parity != NULL)
		kmem_free(entsrc->parity, howmany(entsrc->nblocks, 8));
	bzero(entsrc, sizeof (*entsrc));
}

static void
physmem_ent_gen(physmem_entsrc_t *entsrc)
{
	struct memlist *pmem;
	offset_t offset, poffset;
	pfn_t pfn;
	int i, nbytes, len, ent = 0;
	uint32_t block, oblock;
	hrtime_t ts1, ts2, diff, delta, delta2, delta3;
	uint8_t digest[HASHSIZE];
	HASH_CTX ctx;
	page_t *pp;

	/*
	 * Use each 32-bit quantity in the pool to pick a memory
	 * block to read.
	 */
	for (i = 0; i < RNDPOOLSIZE/4; i++) {

		/* If the pool is "full", stop after one block */
		if (entropy_bits + ent >= CRYPTO_BYTES2BITS(RNDPOOLSIZE)) {
			if (i > 0)
				break;
		}

		/*
		 * This lock protects reading of phys_install.
		 * Any changes to this list, by DR, are done while
		 * holding this lock. So, holding this lock is sufficient
		 * to handle DR also.
		 */
		memlist_read_lock();

		/* We're left with less than 4K of memory after DR */
		ASSERT(entsrc->nblocks > 0);

		/* Pick a memory block to read */
		block = oblock = srndpool[i] % entsrc->nblocks;

		for (pmem = phys_install; pmem != NULL; pmem = pmem->ml_next) {
			if (block < pmem->ml_size / MEMBLOCKSIZE)
				break;
			block -= pmem->ml_size / MEMBLOCKSIZE;
		}

		ASSERT(pmem != NULL);

		offset = pmem->ml_address + block * MEMBLOCKSIZE;

		if (!address_in_memlist(phys_install, offset, MEMBLOCKSIZE)) {
			memlist_read_unlock();
			continue;
		}

		/*
		 * Do an initial check to see if the address is safe
		 */
		if (plat_hold_page(offset >> PAGESHIFT, PLAT_HOLD_NO_LOCK, NULL)
		    == PLAT_HOLD_FAIL) {
			memlist_read_unlock();
			continue;
		}

		/*
		 * Figure out which page to load to read the
		 * memory block.  Load the page and compute the
		 * hash of the memory block.
		 */
		len = MEMBLOCKSIZE;
		ts1 = gethrtime();
		HashInit(&ctx);
		while (len) {
			pfn = offset >> PAGESHIFT;
			poffset = offset & PAGEOFFSET;
			nbytes = PAGESIZE - poffset < len ?
			    PAGESIZE - poffset : len;

			/*
			 * Re-check the offset, and lock the frame.  If the
			 * page was given away after the above check, we'll
			 * just bail out.
			 */
			if (plat_hold_page(pfn, PLAT_HOLD_LOCK, &pp) ==
			    PLAT_HOLD_FAIL)
				break;

			hat_devload(kas.a_hat, entsrc->pmbuf,
			    PAGESIZE, pfn, PROT_READ,
			    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);

			HashUpdate(&ctx, (uint8_t *)entsrc->pmbuf + poffset,
			    nbytes);

			hat_unload(kas.a_hat, entsrc->pmbuf, PAGESIZE,
			    HAT_UNLOAD_UNLOCK);

			plat_release_page(pp);

			len -= nbytes;
			offset += nbytes;
		}
		/* We got our pages. Let the DR roll */
		memlist_read_unlock();

		/* See if we had to bail out due to a page being given away */
		if (len)
			continue;

		HashFinal(digest, &ctx);
		ts2 = gethrtime();

		/*
		 * Compute the time it took to load and hash the
		 * block and compare it against the previous
		 * measurement. The delta of the time values
		 * provides a small amount of entropy.  The
		 * minimum of the first, second, and third order
		 * delta is used to estimate how much entropy
		 * is present.
		 */
		diff = ts2 - ts1;
		delta = diff - entsrc->last_diff;
		if (delta < 0)
			delta = -delta;
		delta2 = delta - entsrc->last_delta;
		if (delta2 < 0)
			delta2 = -delta2;
		delta3 = delta2 - entsrc->last_delta2;
		if (delta3 < 0)
			delta3 = -delta3;
		entsrc->last_diff = diff;
		entsrc->last_delta = delta;
		entsrc->last_delta2 = delta2;

		if (delta > delta2)
			delta = delta2;
		if (delta > delta3)
			delta = delta3;
		delta2 = 0;
		while (delta >>= 1)
			delta2++;
		ent += delta2;

		/*
		 * If the memory block has changed, credit the pool with
		 * the entropy estimate.  The entropy estimate is doubled
		 * because the single-bit checksum misses half the change
		 * on average.
		 */
		if (physmem_parity_update(entsrc->parity, oblock,
		    digest[0] & 1))
			ent += 2 * entsrc->entperblock;

		/* Add the entropy bytes to the pool */
		swrand_add_bytes(digest, HASHSIZE);
		swrand_add_bytes((uint8_t *)&ts1, sizeof (ts1));
		swrand_add_bytes((uint8_t *)&ts2, sizeof (ts2));
	}

	swrand_mix_pool(ent);
}

static int
physmem_parity_update(uint8_t *parity_vec, uint32_t block, int parity)
{
	/* Test and set the parity bit, return 1 if changed */
	if (parity == ((parity_vec[block >> 3] >> (block & 7)) & 1))
		return (0);
	parity_vec[block >> 3] ^= 1 << (block & 7);
	return (1);
}

/* Compute number of memory blocks available to scan */
static void
physmem_count_blocks()
{
	struct memlist *pmem;

	memlist_read_lock();
	entsrc.nblocks = 0;
	for (pmem = phys_install; pmem != NULL; pmem = pmem->ml_next) {
		entsrc.nblocks += pmem->ml_size / MEMBLOCKSIZE;
		if (entsrc.nblocks > MAXMEMBLOCKS) {
			entsrc.nblocks = MAXMEMBLOCKS;
			break;
		}
	}
	memlist_read_unlock();
}

/*
 * Dynamic Reconfiguration call-back functions
 */

/* ARGSUSED */
static void
rnd_dr_callback_post_add(void *arg, pgcnt_t delta)
{
	/* More memory is available now, so update entsrc->nblocks. */
	physmem_count_blocks();
}

/* Call-back routine invoked before the DR starts a memory removal. */
/* ARGSUSED */
static int
rnd_dr_callback_pre_del(void *arg, pgcnt_t delta)
{
	return (0);
}

/* Call-back routine invoked after the DR starts a memory removal. */
/* ARGSUSED */
static void
rnd_dr_callback_post_del(void *arg, pgcnt_t delta, int cancelled)
{
	/* Memory has shrunk, so update entsrc->nblocks. */
	physmem_count_blocks();
}

/* Timeout handling to gather entropy from physmem events */
static void
swrand_schedule_timeout(void)
{
	clock_t ut;	/* time in microseconds */

	ASSERT(MUTEX_HELD(&srndpool_lock));
	/*
	 * The new timeout value is taken from the pool of random bits.
	 * We're merely reading the first 32 bits from the pool here, not
	 * consuming any entropy.
	 * This routine is usually called right after stirring the pool, so
	 * srndpool[0] will have a *fresh* random value each time.
	 * The timeout multiplier value is a random value between 0.7 sec and
	 * 1.748575 sec (0.7 sec + 0xFFFFF microseconds).
	 * The new timeout is TIMEOUT_INTERVAL times that multiplier.
	 */
	ut = 700000 + (clock_t)(srndpool[0] & 0xFFFFF);
	rnd_timeout_id = timeout(rnd_handler, NULL,
	    TIMEOUT_INTERVAL * drv_usectohz(ut));
}

/*ARGSUSED*/
static void
rnd_handler(void *arg)
{
	mutex_enter(&srndpool_lock);

	physmem_ent_gen(&entsrc);
	if (snum_waiters > 0)
		cv_broadcast(&srndpool_read_cv);
	swrand_schedule_timeout();

	mutex_exit(&srndpool_lock);
}
