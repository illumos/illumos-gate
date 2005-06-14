/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	<sys/kmem.h>
#include	<sys/bitmap.h>
#include	<sys/stream.h>
#include	<sys/strsubr.h>
#define	_SUN_TPI_VERSION	2
#include	<sys/tihdr.h>
#include	<sys/suntpi.h>

/*
 * Hash table parameters for tpi_provinfo_table.
 */
#define	TPI_HASH_BITS	4
#define	TPI_NHASH	(1 << TPI_HASH_BITS)

/*
 * Use the first element in the key for the hash.
 */
#define	TPI_HASH(p)	((((uintptr_t *)p)[0] >> tpi_hashshift) % TPI_NHASH)
/*
 * SAMESTR is a very confusing name. LAST_QUEUE is introduced for readability.
 */
#define	LAST_QUEUE(q)	(!SAMESTR(q))

static tpi_provinfo_t	*tpi_provinfo_table[TPI_NHASH];
static kmutex_t		tpi_provinfo_lock;
static int		tpi_hashshift;

/*
 * In most cases there is some transport provider (like tcp or udp) below
 * transport user (like timod or sockets). However, it is possible to construct
 * stream without transport provider (e.g. by pushing timod into FIFO). It is
 * hardly of any use, but this condition was observed with sparcv9 abi tests.
 * To count for such special case, a special tpi_nullprov static data is
 * provided to cache information about such degenerated null-transport case.
 */
static tpi_provinfo_t	tpi_nullprov;	/* Placeholder for null transport */

/*
 * Initialise the TPI support routines.  Called from strinit().
 */
void
tpi_init()
{
	mutex_init(&tpi_provinfo_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Calculate the right shift for hashing a tpi_provinfo_t.
	 */
	tpi_hashshift = highbit(sizeof (tpi_provinfo_t));
}

/*
 * Generate a downstream signature given the write-side queue.  It
 * passes back the size of the generated key in *keylenp.  This routine
 * cannot multithread as it returns a pointer to a static data item.
 *
 * There is no way (in the current module loading infrastructure) to
 * _absolutely_ guarantee that the key below uniquely identifies an
 * arrangement of modules and drivers.  A module _might_ be unloaded and
 * another module _might_ be loaded such that the qi_minfo is at _exactly_
 * same kernel address, and then it _might_ be placed in a transport
 * provider stream in exactly the same configuration (modules above and
 * below all identical) - but it would take quite a few coincidences
 * and modules loading and unloading does not usually happen n times a
 * second...
 */
static void	*
tpi_makekey(queue_t *q, size_t *keylenp)
{
	static uintptr_t	*key	= NULL;
	int			i;

	ASSERT(q != NULL);
	ASSERT(MUTEX_HELD(&tpi_provinfo_lock));

	/* assert this queue is write queue and qprocson() is called before */
	ASSERT((q->q_flag & QREADR) == 0);
	ASSERT(q->q_next != NULL);

	/*
	 * This can be global because tpi_makekey is called with
	 * tpi_provinfo_lock.
	 */
	if (key == NULL)
		key = kmem_alloc((nstrpush + 1) * sizeof (uintptr_t), KM_SLEEP);

	ASSERT(key != NULL);

	/*
	 * Go down q_next to the driver, but no further.  We use the qi_minfo
	 * because we can find in from the queue and it is a stable part of
	 * any driver/module infrastructure.
	 */
	for (i = 0; !LAST_QUEUE(q) && (q = q->q_next) != NULL; ++i) {
		ASSERT(i < nstrpush + 1);
		key[i] = (uintptr_t)q->q_qinfo->qi_minfo;
	}

	/*
	 * Allocate the actual key with the proper length, and pass it
	 * all back.
	 */
	*keylenp = i * sizeof (uintptr_t);
	return ((void *)key);
}

/*
 * Find an existing provider entry given a queue pointer, or allocate a
 * new empty entry if not found.  Because this routine calls kmem_alloc
 * with KM_SLEEP, and because it traverses the q_next pointers of a stream
 * it must be called with a proper user context and within a perimeter
 * which protects the STREAM e.g. an open routine.  This routine always
 * returns a valid pointer.
 */
tpi_provinfo_t	*
tpi_findprov(queue_t *q)
{
	void		*key;
	size_t		keylen;
	tpi_provinfo_t	**tpp;

	mutex_enter(&tpi_provinfo_lock);

	/*
	 * Must hold tpi_provinfo_lock since tpi_makekey() returns a pointer
	 * to static data.
	 */
	key = tpi_makekey(WR(q), &keylen);

	if (keylen == 0) {
		/* there is nothing below us, return special nullprov entry */
		mutex_exit(&tpi_provinfo_lock);
		return (&tpi_nullprov);
	}

	/*
	 * Look for an existing entry, or the place to put a new one.
	 */
	for (tpp = &tpi_provinfo_table[TPI_HASH(key)]; *tpp != NULL;
	    tpp = &(*tpp)->tpi_next) {
		if ((*tpp)->tpi_keylen == keylen &&
		    bcmp((*tpp)->tpi_key, key, keylen) == 0) {
			mutex_exit(&tpi_provinfo_lock);
			return (*tpp);
		}
	}

	/*
	 * Allocate and fill in the new tpi_provinfo_t.
	 */
	*tpp = kmem_zalloc(sizeof (tpi_provinfo_t), KM_SLEEP);
	(*tpp)->tpi_key = kmem_alloc(keylen, KM_SLEEP);
	bcopy(key, (*tpp)->tpi_key, keylen);
	(*tpp)->tpi_keylen = keylen;
	mutex_init(&(*tpp)->tpi_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_exit(&tpi_provinfo_lock);
	return (*tpp);
}

/*
 * Allocate a TPI ACK reusing the old message if possible.
 */
mblk_t	*
tpi_ack_alloc(mblk_t *mp, size_t size, uchar_t db_type, t_scalar_t prim)
{
	mblk_t	*omp	= mp;

	if ((mp = reallocb(mp, size, 0)) == NULL) {
		freemsg(omp);
		return (NULL);
	}
	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	mp->b_datap->db_type = db_type;
	mp->b_wptr = mp->b_rptr + size;
	((union T_primitives *)mp->b_rptr)->type = prim;
	return (mp);
}
