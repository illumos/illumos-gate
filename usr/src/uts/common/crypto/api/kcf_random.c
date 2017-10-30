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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

/*
 * This file implements the interfaces that the /dev/random
 * driver uses for read(2), write(2) and poll(2) on /dev/random or
 * /dev/urandom. It also implements the kernel API - random_add_entropy(),
 * random_add_pseudo_entropy(), random_get_pseudo_bytes()
 * and random_get_bytes().
 *
 * We periodically collect random bits from providers which are registered
 * with the Kernel Cryptographic Framework (kCF) as capable of random
 * number generation. The random bits are maintained in a cache and
 * it is used for high quality random numbers (/dev/random) requests.
 * We pick a provider and call its SPI routine, if the cache does not have
 * enough bytes to satisfy a request.
 *
 * /dev/urandom requests use a software-based generator algorithm that uses the
 * random bits in the cache as a seed. We create one pseudo-random generator
 * (for /dev/urandom) per possible CPU on the system, and use it,
 * kmem-magazine-style, to avoid cache line contention.
 *
 * LOCKING HIERARCHY:
 *	1) rmp->rm_mag.rm_lock protects the per-cpu pseudo-random generators.
 * 	2) rndpool_lock protects the high-quality randomness pool.
 *		It may be locked while a rmp->rm_mag.rm_lock is held.
 *
 * A history note: The kernel API and the software-based algorithms in this
 * file used to be part of the /dev/random driver.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/crypto/ioctladmin.h>
#include <sys/random.h>
#include <sys/sha1.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/taskq.h>
#include <rng/fips_random.h>

#define	RNDPOOLSIZE		1024	/* Pool size in bytes */
#define	MINEXTRACTBYTES		20
#define	MAXEXTRACTBYTES		1024
#define	PRNG_MAXOBLOCKS		1310720	/* Max output block per prng key */
#define	TIMEOUT_INTERVAL	5	/* Periodic mixing interval in secs */

typedef enum    extract_type {
	NONBLOCK_EXTRACT,
	BLOCKING_EXTRACT,
	ALWAYS_EXTRACT
} extract_type_t;

/*
 * Hash-algo generic definitions. For now, they are SHA1's. We use SHA1
 * routines directly instead of using k-API because we can't return any
 * error code in /dev/urandom case and we can get an error using k-API
 * if a mechanism is disabled.
 */
#define	HASHSIZE		20
#define	HASH_CTX		SHA1_CTX
#define	HashInit(ctx)		SHA1Init((ctx))
#define	HashUpdate(ctx, p, s)	SHA1Update((ctx), (p), (s))
#define	HashFinal(d, ctx)	SHA1Final((d), (ctx))

/* HMAC-SHA1 */
#define	HMAC_KEYSIZE			20

/*
 * Cache of random bytes implemented as a circular buffer. findex and rindex
 * track the front and back of the circular buffer.
 */
uint8_t rndpool[RNDPOOLSIZE];
static int findex, rindex;
static int rnbyte_cnt;		/* Number of bytes in the cache */

static kmutex_t rndpool_lock;	/* protects r/w accesses to the cache, */
				/* and the global variables */
static kcondvar_t rndpool_read_cv; /* serializes poll/read syscalls */
static int num_waiters;		/* #threads waiting to read from /dev/random */

static struct pollhead rnd_pollhead;
/* LINTED E_STATIC_UNUSED */
static timeout_id_t kcf_rndtimeout_id;
static crypto_mech_type_t rngmech_type = CRYPTO_MECH_INVALID;
rnd_stats_t rnd_stats;
static boolean_t rng_prov_found = B_TRUE;
static boolean_t rng_ok_to_log = B_TRUE;
static boolean_t rngprov_task_idle = B_TRUE;

static void rndc_addbytes(uint8_t *, size_t);
static void rndc_getbytes(uint8_t *ptr, size_t len);
static void rnd_handler(void *);
static void rnd_alloc_magazines(void);
static void rnd_fips_discard_initial(void);
static void rnd_init2(void *);
static void rnd_schedule_timeout(void);

/*
 * Called from kcf:_init()
 */
void
kcf_rnd_init()
{
	hrtime_t ts;
	time_t now;

	mutex_init(&rndpool_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rndpool_read_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * Add bytes to the cache using
	 * . 2 unpredictable times: high resolution time since the boot-time,
	 *   and the current time-of-the day.
	 * This is used only to make the timeout value in the timer
	 * unpredictable.
	 */
	ts = gethrtime();
	rndc_addbytes((uint8_t *)&ts, sizeof (ts));

	(void) drv_getparm(TIME, &now);
	rndc_addbytes((uint8_t *)&now, sizeof (now));

	rnbyte_cnt = 0;
	findex = rindex = 0;
	num_waiters = 0;

	rnd_alloc_magazines();

	(void) taskq_dispatch(system_taskq, rnd_init2, NULL, TQ_SLEEP);
}

/*
 * This is called via the system taskq, so that we can do further
 * initializations that have to wait until the kcf module itself is
 * done loading.  (After kcf:_init returns.)
 */
static void
rnd_init2(void *unused)
{

	_NOTE(ARGUNUSED(unused));

	/*
	 * This will load a randomness provider; typically "swrand",
	 * but could be another provider if so configured.
	 */
	rngmech_type = crypto_mech2id(SUN_RANDOM);

	/* Update rng_prov_found etc. */
	(void) kcf_rngprov_check();

	/* FIPS 140-2 init. */
	rnd_fips_discard_initial();

	/* Start rnd_handler calls. */
	rnd_schedule_timeout();
}

/*
 * Return TRUE if at least one provider exists that can
 * supply random numbers.
 */
boolean_t
kcf_rngprov_check(void)
{
	int rv;
	kcf_provider_desc_t *pd;

	if ((pd = kcf_get_mech_provider(rngmech_type, NULL, NULL, &rv,
	    NULL, CRYPTO_FG_RANDOM, 0)) != NULL) {
		KCF_PROV_REFRELE(pd);
		/*
		 * We logged a warning once about no provider being available
		 * and now a provider became available. So, set the flag so
		 * that we can log again if the problem recurs.
		 */
		rng_ok_to_log = B_TRUE;
		rng_prov_found = B_TRUE;
		return (B_TRUE);
	} else {
		rng_prov_found = B_FALSE;
		return (B_FALSE);
	}
}

/*
 * Pick a software-based provider and submit a request to seed
 * its random number generator.
 */
static void
rngprov_seed(uint8_t *buf, int len, uint_t entropy_est, uint32_t flags)
{
	kcf_provider_desc_t *pd = NULL;

	if (kcf_get_sw_prov(rngmech_type, &pd, NULL, B_FALSE) ==
	    CRYPTO_SUCCESS) {
		(void) KCF_PROV_SEED_RANDOM(pd, pd->pd_sid, buf, len,
		    entropy_est, flags, NULL);
		KCF_PROV_REFRELE(pd);
	}
}

/*
 * This routine is called for blocking reads.
 *
 * The argument is_taskq_thr indicates whether the caller is
 * the taskq thread dispatched by the timeout handler routine.
 * In this case, we cycle through all the providers
 * submitting a request to each provider to generate random numbers.
 *
 * For other cases, we pick a provider and submit a request to generate
 * random numbers. We retry using another provider if we get an error.
 *
 * Returns the number of bytes that are written to 'ptr'. Returns -1
 * if no provider is found. ptr and need are unchanged.
 */
static int
rngprov_getbytes(uint8_t *ptr, size_t need, boolean_t is_taskq_thr)
{
	int rv;
	int prov_cnt = 0;
	int total_bytes = 0;
	kcf_provider_desc_t *pd;
	kcf_req_params_t params;
	kcf_prov_tried_t *list = NULL;

	while ((pd = kcf_get_mech_provider(rngmech_type, NULL, NULL, &rv,
	    list, CRYPTO_FG_RANDOM, 0)) != NULL) {

		prov_cnt++;

		KCF_WRAP_RANDOM_OPS_PARAMS(&params, KCF_OP_RANDOM_GENERATE,
		    pd->pd_sid, ptr, need, 0, 0);
		rv = kcf_submit_request(pd, NULL, NULL, &params, B_FALSE);
		ASSERT(rv != CRYPTO_QUEUED);

		if (rv == CRYPTO_SUCCESS) {
			total_bytes += need;
			if (is_taskq_thr)
				rndc_addbytes(ptr, need);
			else {
				KCF_PROV_REFRELE(pd);
				break;
			}
		}

		if (is_taskq_thr || rv != CRYPTO_SUCCESS) {
			/* Add pd to the linked list of providers tried. */
			if (kcf_insert_triedlist(&list, pd, KM_SLEEP) == NULL) {
				KCF_PROV_REFRELE(pd);
				break;
			}
		}

	}

	if (list != NULL)
		kcf_free_triedlist(list);

	if (prov_cnt == 0) { /* no provider could be found. */
		rng_prov_found = B_FALSE;
		return (-1);
	} else {
		rng_prov_found = B_TRUE;
		/* See comments in kcf_rngprov_check() */
		rng_ok_to_log = B_TRUE;
	}

	return (total_bytes);
}

static void
notify_done(void *arg, int rv)
{
	uchar_t *rndbuf = arg;

	if (rv == CRYPTO_SUCCESS)
		rndc_addbytes(rndbuf, MINEXTRACTBYTES);

	bzero(rndbuf, MINEXTRACTBYTES);
	kmem_free(rndbuf, MINEXTRACTBYTES);
}

/*
 * Cycle through all the providers submitting a request to each provider
 * to generate random numbers. This is called for the modes - NONBLOCK_EXTRACT
 * and ALWAYS_EXTRACT.
 *
 * Returns the number of bytes that are written to 'ptr'. Returns -1
 * if no provider is found. ptr and len are unchanged.
 */
static int
rngprov_getbytes_nblk(uint8_t *ptr, size_t len)
{
	int rv, total_bytes;
	size_t blen;
	uchar_t *rndbuf;
	kcf_provider_desc_t *pd;
	kcf_req_params_t params;
	crypto_call_req_t req;
	kcf_prov_tried_t *list = NULL;
	int prov_cnt = 0;

	blen = 0;
	total_bytes = 0;
	req.cr_flag = CRYPTO_SKIP_REQID;
	req.cr_callback_func = notify_done;

	while ((pd = kcf_get_mech_provider(rngmech_type, NULL, NULL, &rv,
	    list, CRYPTO_FG_RANDOM, 0)) != NULL) {

		prov_cnt ++;
		switch (pd->pd_prov_type) {
		case CRYPTO_HW_PROVIDER:
			/*
			 * We have to allocate a buffer here as we can not
			 * assume that the input buffer will remain valid
			 * when the callback comes. We use a fixed size buffer
			 * to simplify the book keeping.
			 */
			rndbuf = kmem_alloc(MINEXTRACTBYTES, KM_NOSLEEP);
			if (rndbuf == NULL) {
				KCF_PROV_REFRELE(pd);
				if (list != NULL)
					kcf_free_triedlist(list);
				return (total_bytes);
			}
			req.cr_callback_arg = rndbuf;
			KCF_WRAP_RANDOM_OPS_PARAMS(&params,
			    KCF_OP_RANDOM_GENERATE,
			    pd->pd_sid, rndbuf, MINEXTRACTBYTES, 0, 0);
			break;

		case CRYPTO_SW_PROVIDER:
			/*
			 * We do not need to allocate a buffer in the software
			 * provider case as there is no callback involved. We
			 * avoid any extra data copy by directly passing 'ptr'.
			 */
			KCF_WRAP_RANDOM_OPS_PARAMS(&params,
			    KCF_OP_RANDOM_GENERATE,
			    pd->pd_sid, ptr, len, 0, 0);
			break;
		}

		rv = kcf_submit_request(pd, NULL, &req, &params, B_FALSE);
		if (rv == CRYPTO_SUCCESS) {
			switch (pd->pd_prov_type) {
			case CRYPTO_HW_PROVIDER:
				/*
				 * Since we have the input buffer handy,
				 * we directly copy to it rather than
				 * adding to the pool.
				 */
				blen = min(MINEXTRACTBYTES, len);
				bcopy(rndbuf, ptr, blen);
				if (len < MINEXTRACTBYTES)
					rndc_addbytes(rndbuf + len,
					    MINEXTRACTBYTES - len);
				ptr += blen;
				len -= blen;
				total_bytes += blen;
				break;

			case CRYPTO_SW_PROVIDER:
				total_bytes += len;
				len = 0;
				break;
			}
		}

		/*
		 * We free the buffer in the callback routine
		 * for the CRYPTO_QUEUED case.
		 */
		if (pd->pd_prov_type == CRYPTO_HW_PROVIDER &&
		    rv != CRYPTO_QUEUED) {
			bzero(rndbuf, MINEXTRACTBYTES);
			kmem_free(rndbuf, MINEXTRACTBYTES);
		}

		if (len == 0) {
			KCF_PROV_REFRELE(pd);
			break;
		}

		if (rv != CRYPTO_SUCCESS) {
			/* Add pd to the linked list of providers tried. */
			if (kcf_insert_triedlist(&list, pd, KM_NOSLEEP) ==
			    NULL) {
				KCF_PROV_REFRELE(pd);
				break;
			}
		}
	}

	if (list != NULL) {
		kcf_free_triedlist(list);
	}

	if (prov_cnt == 0) { /* no provider could be found. */
		rng_prov_found = B_FALSE;
		return (-1);
	} else {
		rng_prov_found = B_TRUE;
		/* See comments in kcf_rngprov_check() */
		rng_ok_to_log = B_TRUE;
	}

	return (total_bytes);
}

static void
rngprov_task(void *arg)
{
	int len = (int)(uintptr_t)arg;
	uchar_t tbuf[MAXEXTRACTBYTES];

	ASSERT(len <= MAXEXTRACTBYTES);
	(void) rngprov_getbytes(tbuf, len, B_TRUE);
	rngprov_task_idle = B_TRUE;
}

/*
 * Returns "len" random or pseudo-random bytes in *ptr.
 * Will block if not enough random bytes are available and the
 * call is blocking.
 *
 * Called with rndpool_lock held (allowing caller to do optimistic locking;
 * releases the lock before return).
 */
static int
rnd_get_bytes(uint8_t *ptr, size_t len, extract_type_t how)
{
	size_t	bytes;
	int	got;

	ASSERT(mutex_owned(&rndpool_lock));
	/*
	 * Check if the request can be satisfied from the cache
	 * of random bytes.
	 */
	if (len <= rnbyte_cnt) {
		rndc_getbytes(ptr, len);
		mutex_exit(&rndpool_lock);
		return (0);
	}
	mutex_exit(&rndpool_lock);

	switch (how) {
	case BLOCKING_EXTRACT:
		if ((got = rngprov_getbytes(ptr, len, B_FALSE)) == -1)
			break;	/* No provider found */

		if (got == len)
			return (0);
		len -= got;
		ptr += got;
		break;

	case NONBLOCK_EXTRACT:
	case ALWAYS_EXTRACT:
		if ((got = rngprov_getbytes_nblk(ptr, len)) == -1) {
			/* No provider found */
			if (how == NONBLOCK_EXTRACT) {
				return (EAGAIN);
			}
		} else {
			if (got == len)
				return (0);
			len -= got;
			ptr += got;
		}
		if (how == NONBLOCK_EXTRACT && (rnbyte_cnt < len))
			return (EAGAIN);
		break;
	}

	mutex_enter(&rndpool_lock);
	while (len > 0) {
		if (how == BLOCKING_EXTRACT) {
			/* Check if there is enough */
			while (rnbyte_cnt < MINEXTRACTBYTES) {
				num_waiters++;
				if (cv_wait_sig(&rndpool_read_cv,
				    &rndpool_lock) == 0) {
					num_waiters--;
					mutex_exit(&rndpool_lock);
					return (EINTR);
				}
				num_waiters--;
			}
		}

		/* Figure out how many bytes to extract */
		bytes = min(len, rnbyte_cnt);
		rndc_getbytes(ptr, bytes);

		len -= bytes;
		ptr += bytes;

		if (len > 0 && how == ALWAYS_EXTRACT) {
			/*
			 * There are not enough bytes, but we can not block.
			 * This only happens in the case of /dev/urandom which
			 * runs an additional generation algorithm. So, there
			 * is no problem.
			 */
			while (len > 0) {
				*ptr = rndpool[findex];
				ptr++; len--;
				rindex = findex = (findex + 1) &
				    (RNDPOOLSIZE - 1);
			}
			break;
		}
	}

	mutex_exit(&rndpool_lock);
	return (0);
}

int
kcf_rnd_get_bytes(uint8_t *ptr, size_t len, boolean_t noblock)
{
	extract_type_t how;
	int error;

	how = noblock ? NONBLOCK_EXTRACT : BLOCKING_EXTRACT;
	mutex_enter(&rndpool_lock);
	if ((error = rnd_get_bytes(ptr, len, how)) != 0)
		return (error);

	BUMP_RND_STATS(rs_rndOut, len);
	return (0);
}

/*
 * Revisit this if the structs grow or we come up with a better way
 * of cache-line-padding structures.
 */
#define	RND_CPU_CACHE_SIZE	64
#define	RND_CPU_PAD_SIZE	RND_CPU_CACHE_SIZE*6
#define	RND_CPU_PAD (RND_CPU_PAD_SIZE - \
	sizeof (rndmag_t))
/*
 * Per-CPU random state.  Somewhat like like kmem's magazines, this provides
 * a per-CPU instance of the pseudo-random generator.  We have it much easier
 * than kmem, as we can afford to "leak" random bits if a CPU is DR'ed out.
 *
 * Note that this usage is preemption-safe; a thread
 * entering a critical section remembers which generator it locked
 * and unlocks the same one; should it be preempted and wind up running on
 * a different CPU, there will be a brief period of increased contention
 * before it exits the critical section but nothing will melt.
 */
typedef struct rndmag_s
{
	kmutex_t	rm_lock;
	uint8_t		*rm_buffer;	/* Start of buffer */
	uint8_t		*rm_eptr;	/* End of buffer */
	uint8_t		*rm_rptr;	/* Current read pointer */
	uint32_t	rm_oblocks;	/* time to rekey? */
	uint32_t	rm_ofuzz;	/* Rekey backoff state */
	uint32_t	rm_olimit;	/* Hard rekey limit */
	rnd_stats_t	rm_stats;	/* Per-CPU Statistics */
	uint32_t	rm_key[HASHSIZE/BYTES_IN_WORD];	/* FIPS XKEY */
	uint32_t	rm_seed[HASHSIZE/BYTES_IN_WORD]; /* seed for rekey */
	uint32_t	rm_previous[HASHSIZE/BYTES_IN_WORD]; /* prev random */
} rndmag_t;

typedef struct rndmag_pad_s
{
	rndmag_t	rm_mag;
	uint8_t		rm_pad[RND_CPU_PAD];
} rndmag_pad_t;

/*
 * Generate random bytes for /dev/urandom by applying the
 * FIPS 186-2 algorithm with a key created from bytes extracted
 * from the pool.  A maximum of PRNG_MAXOBLOCKS output blocks
 * is generated before a new key is obtained.
 *
 * Note that callers to this routine are likely to assume it can't fail.
 *
 * Called with rmp locked; releases lock.
 */
static int
rnd_generate_pseudo_bytes(rndmag_pad_t *rmp, uint8_t *ptr, size_t len)
{
	size_t bytes = len, size;
	int nblock;
	uint32_t oblocks;
	uint32_t tempout[HASHSIZE/BYTES_IN_WORD];
	uint32_t seed[HASHSIZE/BYTES_IN_WORD];
	int i;
	hrtime_t timestamp;
	uint8_t *src, *dst;

	ASSERT(mutex_owned(&rmp->rm_mag.rm_lock));

	/* Nothing is being asked */
	if (len == 0) {
		mutex_exit(&rmp->rm_mag.rm_lock);
		return (0);
	}

	nblock = howmany(len, HASHSIZE);

	rmp->rm_mag.rm_oblocks += nblock;
	oblocks = rmp->rm_mag.rm_oblocks;

	do {
		if (oblocks >= rmp->rm_mag.rm_olimit) {

			/*
			 * Contention-avoiding rekey: see if
			 * the pool is locked, and if so, wait a bit.
			 * Do an 'exponential back-in' to ensure we don't
			 * run too long without rekey.
			 */
			if (rmp->rm_mag.rm_ofuzz) {
				/*
				 * Decaying exponential back-in for rekey.
				 */
				if ((rnbyte_cnt < MINEXTRACTBYTES) ||
				    (!mutex_tryenter(&rndpool_lock))) {
					rmp->rm_mag.rm_olimit +=
					    rmp->rm_mag.rm_ofuzz;
					rmp->rm_mag.rm_ofuzz >>= 1;
					goto punt;
				}
			} else {
				mutex_enter(&rndpool_lock);
			}

			/* Get a new chunk of entropy */
			(void) rnd_get_bytes((uint8_t *)rmp->rm_mag.rm_key,
			    HMAC_KEYSIZE, ALWAYS_EXTRACT);

			rmp->rm_mag.rm_olimit = PRNG_MAXOBLOCKS/2;
			rmp->rm_mag.rm_ofuzz = PRNG_MAXOBLOCKS/4;
			oblocks = 0;
			rmp->rm_mag.rm_oblocks = nblock;
		}
punt:
		timestamp = gethrtime();

		src = (uint8_t *)&timestamp;
		dst = (uint8_t *)rmp->rm_mag.rm_seed;

		for (i = 0; i < HASHSIZE; i++) {
			dst[i] ^= src[i % sizeof (timestamp)];
		}

		bcopy(rmp->rm_mag.rm_seed, seed, HASHSIZE);

		fips_random_inner(rmp->rm_mag.rm_key, tempout,
		    seed);

		if (bytes >= HASHSIZE) {
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
			if (tempout[i] != rmp->rm_mag.rm_previous[i])
				break;
		}
		if (i == HASHSIZE/BYTES_IN_WORD) {
			cmn_err(CE_WARN, "kcf_random: The value of 160-bit "
			    "block random bytes are same as the previous "
			    "one.\n");
			/* discard random bytes and return error */
			mutex_exit(&rmp->rm_mag.rm_lock);
			return (EIO);
		}

		bcopy(tempout, rmp->rm_mag.rm_previous,
		    HASHSIZE);

		bcopy(tempout, ptr, size);
		ptr += size;
		bytes -= size;
		oblocks++;
		nblock--;
	} while (bytes > 0);

	/* Zero out sensitive information */
	bzero(seed, HASHSIZE);
	bzero(tempout, HASHSIZE);
	mutex_exit(&rmp->rm_mag.rm_lock);
	return (0);
}

/*
 * Per-CPU Random magazines.
 */
static rndmag_pad_t *rndmag;
static uint8_t	*rndbuf;
static size_t 	rndmag_total;
/*
 * common/os/cpu.c says that platform support code can shrinkwrap
 * max_ncpus.  On the off chance that we get loaded very early, we
 * read it exactly once, to copy it here.
 */
static uint32_t	random_max_ncpus = 0;

/*
 * Boot-time tunables, for experimentation.
 */
size_t	rndmag_threshold = 2560;
size_t	rndbuf_len = 5120;
size_t	rndmag_size = 1280;


int
kcf_rnd_get_pseudo_bytes(uint8_t *ptr, size_t len)
{
	rndmag_pad_t *rmp;
	uint8_t *cptr, *eptr;

	/*
	 * Anyone who asks for zero bytes of randomness should get slapped.
	 */
	ASSERT(len > 0);

	/*
	 * Fast path.
	 */
	for (;;) {
		rmp = &rndmag[CPU->cpu_seqid];
		mutex_enter(&rmp->rm_mag.rm_lock);

		/*
		 * Big requests bypass buffer and tail-call the
		 * generate routine directly.
		 */
		if (len > rndmag_threshold) {
			BUMP_CPU_RND_STATS(rmp, rs_urndOut, len);
			return (rnd_generate_pseudo_bytes(rmp, ptr, len));
		}

		cptr = rmp->rm_mag.rm_rptr;
		eptr = cptr + len;

		if (eptr <= rmp->rm_mag.rm_eptr) {
			rmp->rm_mag.rm_rptr = eptr;
			bcopy(cptr, ptr, len);
			BUMP_CPU_RND_STATS(rmp, rs_urndOut, len);
			mutex_exit(&rmp->rm_mag.rm_lock);

			return (0);
		}
		/*
		 * End fast path.
		 */
		rmp->rm_mag.rm_rptr = rmp->rm_mag.rm_buffer;
		/*
		 * Note:  We assume the generate routine always succeeds
		 * in this case (because it does at present..)
		 * It also always releases rm_lock.
		 */
		(void) rnd_generate_pseudo_bytes(rmp, rmp->rm_mag.rm_buffer,
		    rndbuf_len);
	}
}

/*
 * We set up (empty) magazines for all of max_ncpus, possibly wasting a
 * little memory on big systems that don't have the full set installed.
 * See above;  "empty" means "rptr equal to eptr"; this will trigger the
 * refill path in rnd_get_pseudo_bytes above on the first call for each CPU.
 *
 * TODO: make rndmag_size tunable at run time!
 */
static void
rnd_alloc_magazines()
{
	rndmag_pad_t *rmp;
	int i;

	rndbuf_len = roundup(rndbuf_len, HASHSIZE);
	if (rndmag_size < rndbuf_len)
		rndmag_size = rndbuf_len;
	rndmag_size = roundup(rndmag_size, RND_CPU_CACHE_SIZE);

	random_max_ncpus = max_ncpus;
	rndmag_total = rndmag_size * random_max_ncpus;

	rndbuf = kmem_alloc(rndmag_total, KM_SLEEP);
	rndmag = kmem_zalloc(sizeof (rndmag_pad_t) * random_max_ncpus,
	    KM_SLEEP);

	for (i = 0; i < random_max_ncpus; i++) {
		uint8_t *buf;

		rmp = &rndmag[i];
		mutex_init(&rmp->rm_mag.rm_lock, NULL, MUTEX_DRIVER, NULL);

		buf = rndbuf + i * rndmag_size;

		rmp->rm_mag.rm_buffer = buf;
		rmp->rm_mag.rm_eptr = buf + rndbuf_len;
		rmp->rm_mag.rm_rptr = buf + rndbuf_len;
		rmp->rm_mag.rm_oblocks = 1;
	}
}

/*
 * FIPS 140-2: the first n-bit (n > 15) block generated
 * after power-up, initialization, or reset shall not
 * be used, but shall be saved for comparison.
 */
static void
rnd_fips_discard_initial(void)
{
	uint8_t discard_buf[HASHSIZE];
	rndmag_pad_t *rmp;
	int i;

	for (i = 0; i < random_max_ncpus; i++) {
		rmp = &rndmag[i];

		/* rnd_get_bytes() will call mutex_exit(&rndpool_lock) */
		mutex_enter(&rndpool_lock);
		(void) rnd_get_bytes(discard_buf,
		    HMAC_KEYSIZE, ALWAYS_EXTRACT);
		bcopy(discard_buf, rmp->rm_mag.rm_previous,
		    HMAC_KEYSIZE);
		/* rnd_get_bytes() will call mutex_exit(&rndpool_lock) */
		mutex_enter(&rndpool_lock);
		(void) rnd_get_bytes((uint8_t *)rmp->rm_mag.rm_key,
		    HMAC_KEYSIZE, ALWAYS_EXTRACT);
		/* rnd_get_bytes() will call mutex_exit(&rndpool_lock) */
		mutex_enter(&rndpool_lock);
		(void) rnd_get_bytes((uint8_t *)rmp->rm_mag.rm_seed,
		    HMAC_KEYSIZE, ALWAYS_EXTRACT);
	}
}

static void
rnd_schedule_timeout(void)
{
	clock_t ut;	/* time in microseconds */

	/*
	 * The new timeout value is taken from the buffer of random bytes.
	 * We're merely reading the first 32 bits from the buffer here, not
	 * consuming any random bytes.
	 * The timeout multiplier value is a random value between 0.5 sec and
	 * 1.544480 sec (0.5 sec + 0xFF000 microseconds).
	 * The new timeout is TIMEOUT_INTERVAL times that multiplier.
	 */
	ut = 500000 + (clock_t)((((uint32_t)rndpool[findex]) << 12) & 0xFF000);
	kcf_rndtimeout_id = timeout(rnd_handler, NULL,
	    TIMEOUT_INTERVAL * drv_usectohz(ut));
}

/*
 * Called from the driver for a poll on /dev/random
 * . POLLOUT always succeeds.
 * . POLLIN and POLLRDNORM will block until a
 *   minimum amount of entropy is available.
 *
 * &rnd_pollhead is passed in *phpp in order to indicate the calling thread
 * will block. When enough random bytes are available, later, the timeout
 * handler routine will issue the pollwakeup() calls.
 */
void
kcf_rnd_chpoll(short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	*reventsp = events & POLLOUT;

	if (events & (POLLIN | POLLRDNORM)) {
		/*
		 * Sampling of rnbyte_cnt is an atomic
		 * operation. Hence we do not need any locking.
		 */
		if (rnbyte_cnt >= MINEXTRACTBYTES)
			*reventsp |= (events & (POLLIN | POLLRDNORM));
	}

	if ((*reventsp == 0 && !anyyet) || (events & POLLET))
		*phpp = &rnd_pollhead;
}

/*ARGSUSED*/
static void
rnd_handler(void *arg)
{
	int len = 0;

	if (!rng_prov_found && rng_ok_to_log) {
		cmn_err(CE_WARN, "No randomness provider enabled for "
		    "/dev/random. Use cryptoadm(1M) to enable a provider.");
		rng_ok_to_log = B_FALSE;
	}

	if (num_waiters > 0)
		/*
		 * Note: len has no relationship with how many bytes
		 * a poll thread needs.
		 */
		len = MAXEXTRACTBYTES;
	else if (rnbyte_cnt < RNDPOOLSIZE)
		len = MINEXTRACTBYTES;

	/*
	 * Only one thread gets to set rngprov_task_idle at a given point
	 * of time and the order of the writes is defined. Also, it is OK
	 * if we read an older value of it and skip the dispatch once
	 * since we will get the correct value during the next time here.
	 * So, no locking is needed here.
	 */
	if (len > 0 && rngprov_task_idle) {
		rngprov_task_idle = B_FALSE;

		/*
		 * It is OK if taskq_dispatch fails here. We will retry
		 * the next time around. Meanwhile, a thread doing a
		 * read() will go to the provider directly, if the
		 * cache becomes empty.
		 */
		if (taskq_dispatch(system_taskq, rngprov_task,
		    (void *)(uintptr_t)len, TQ_NOSLEEP | TQ_NOQUEUE) == 0) {
			rngprov_task_idle = B_TRUE;
		}
	}

	mutex_enter(&rndpool_lock);
	/*
	 * Wake up threads waiting in poll() or for enough accumulated
	 * random bytes to read from /dev/random. In case a poll() is
	 * concurrent with a read(), the polling process may be woken up
	 * indicating that enough randomness is now available for reading,
	 * and another process *steals* the bits from the pool, causing the
	 * subsequent read() from the first process to block. It is acceptable
	 * since the blocking will eventually end, after the timeout
	 * has expired enough times to honor the read.
	 *
	 * Note - Since we hold the rndpool_lock across the pollwakeup() call
	 * we MUST NOT grab the rndpool_lock in kcf_rndchpoll().
	 */
	if (rnbyte_cnt >= MINEXTRACTBYTES)
		pollwakeup(&rnd_pollhead, POLLIN | POLLRDNORM);

	if (num_waiters > 0)
		cv_broadcast(&rndpool_read_cv);
	mutex_exit(&rndpool_lock);

	rnd_schedule_timeout();
}

static void
rndc_addbytes(uint8_t *ptr, size_t len)
{
	ASSERT(ptr != NULL && len > 0);
	ASSERT(rnbyte_cnt <= RNDPOOLSIZE);

	mutex_enter(&rndpool_lock);
	while ((len > 0) && (rnbyte_cnt < RNDPOOLSIZE)) {
		rndpool[rindex] ^= *ptr;
		ptr++; len--;
		rindex = (rindex + 1) & (RNDPOOLSIZE - 1);
		rnbyte_cnt++;
	}

	/* Handle buffer full case */
	while (len > 0) {
		rndpool[rindex] ^= *ptr;
		ptr++; len--;
		findex = rindex = (rindex + 1) & (RNDPOOLSIZE - 1);
	}
	mutex_exit(&rndpool_lock);
}

/*
 * Caller should check len <= rnbyte_cnt under the
 * rndpool_lock before calling.
 */
static void
rndc_getbytes(uint8_t *ptr, size_t len)
{
	ASSERT(MUTEX_HELD(&rndpool_lock));
	ASSERT(len <= rnbyte_cnt && rnbyte_cnt <= RNDPOOLSIZE);

	BUMP_RND_STATS(rs_rndcOut, len);

	while (len > 0) {
		*ptr = rndpool[findex];
		ptr++; len--;
		findex = (findex + 1) & (RNDPOOLSIZE - 1);
		rnbyte_cnt--;
	}
}

/* Random number exported entry points */

/*
 * Mix the supplied bytes into the entropy pool of a kCF
 * RNG provider.
 */
int
random_add_pseudo_entropy(uint8_t *ptr, size_t len, uint_t entropy_est)
{
	if (len < 1)
		return (-1);

	rngprov_seed(ptr, len, entropy_est, 0);

	return (0);
}

/*
 * Mix the supplied bytes into the entropy pool of a kCF
 * RNG provider. Mix immediately.
 */
int
random_add_entropy(uint8_t *ptr, size_t len, uint_t entropy_est)
{
	if (len < 1)
		return (-1);

	rngprov_seed(ptr, len, entropy_est, CRYPTO_SEED_NOW);

	return (0);
}

/*
 * Get bytes from the /dev/urandom generator. This function
 * always succeeds. Returns 0.
 */
int
random_get_pseudo_bytes(uint8_t *ptr, size_t len)
{
	ASSERT(!mutex_owned(&rndpool_lock));

	if (len < 1)
		return (0);
	return (kcf_rnd_get_pseudo_bytes(ptr, len));
}

/*
 * Get bytes from the /dev/random generator. Returns 0
 * on success. Returns EAGAIN if there is insufficient entropy.
 */
int
random_get_bytes(uint8_t *ptr, size_t len)
{
	ASSERT(!mutex_owned(&rndpool_lock));

	if (len < 1)
		return (0);
	return (kcf_rnd_get_bytes(ptr, len, B_TRUE));
}

int
random_get_blocking_bytes(uint8_t *ptr, size_t len)
{
	ASSERT(!mutex_owned(&rndpool_lock));

	if (len < 1)
		return (0);
	return (kcf_rnd_get_bytes(ptr, len, B_FALSE));
}
