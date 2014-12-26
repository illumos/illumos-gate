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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 */

#ifndef	_SYS_RANDOM_H
#define	_SYS_RANDOM_H

#include <sys/types.h>
#include <sys/atomic.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* stats for the random number devices, /dev/random and /dev/urandom. */
typedef struct rnd_stats {
	uint64_t	rs_rndOut;	/* Bytes generated for /dev/random */
	uint64_t	rs_rndcOut;	/* Bytes read from /dev/random cache */
	uint64_t	rs_urndOut;	/* Bytes generated for /dev/urandom */
} rnd_stats_t;

/* stats for the kernel random number provider, swrand. */
typedef struct swrand_stats {
	uint32_t	ss_entEst;	/* Entropy estimate in bits */
	uint64_t	ss_entIn;	/* Entropy bits added to pool */
	uint64_t	ss_entOut;	/* Entropy bits extracted from pool */
	uint64_t	ss_bytesIn;	/* Total data bytes added to pool */
	uint64_t	ss_bytesOut;	/* Total data bytes extracted from */
					/* the pool */
} swrand_stats_t;

#ifdef	_KERNEL

#define	BUMP_CPU_RND_STATS(rm, x, v)    (((rm)->rm_mag.rm_stats).x += (v))
#define	BUMP_RND_STATS(x, v)	atomic_add_64(&(rnd_stats).x, (v))
#define	BUMP_SWRAND_STATS(x, v)	atomic_add_64(&(swrand_stats).x, (v))

extern int random_add_entropy(uint8_t *, size_t, uint_t);
extern int random_get_bytes(uint8_t *, size_t);
extern int random_get_blocking_bytes(uint8_t *, size_t);
extern int random_get_pseudo_bytes(uint8_t *, size_t);

#endif /* _KERNEL */

/*
 * Flags for the getrandom system call. Note, we may want to move these
 * definitions if we expose getrandom(2) into a public system call.
 */
#define	GRND_NONBLOCK	0x0001		/* O_NONBLOCK equiv */
#define	GRND_RANDOM	0x0002		/* Use /dev/random, not /dev/urandom */
extern int getrandom(void *, size_t, int);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_RANDOM_H */
