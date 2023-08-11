/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Some minimal streams mblk_t management functions needed by
 * ksocket_sendmblk:  esballoca(), freemsg(), ...
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <umem.h>

static void
lastfree(mblk_t *mp, dblk_t *db)
{
	frtn_t *frp = db->db_frtnp;

	ASSERT(db->db_mblk == mp);
	ASSERT(mp->b_datap == db);

	ASSERT(frp != NULL);
	frp->free_func(frp->free_arg);

	kmem_free(mp, sizeof (*mp));
	kmem_free(db, sizeof (*db));
}


mblk_t *
esballoca(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	dblk_t *db;
	mblk_t *mp;

	db = kmem_zalloc(sizeof (*db), KM_SLEEP);
	mp = kmem_zalloc(sizeof (*mp), KM_SLEEP);

	mp->b_datap = db;
	db->db_mblk = mp;

	db->db_base = base;
	db->db_lim = base + size;
	db->db_free = db->db_lastfree = lastfree;
	db->db_frtnp = frp;

	/*
	 * streams.c uses these weird macro:
	 * DBLK_RTFU_WORD(dbp) = db_rtfu
	 * where db_rtfu = DBLK_RTFU(1, M_DATA, 0, 0)
	 * Probably only care about db_ref
	 */
	db->db_ref = 1;

	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	mp->b_rptr = mp->b_wptr = base;
	mp->b_queue = NULL;

	return (mp);
}

/*
 * Same as esballoca() but sleeps waiting for memory.
 * (in here, both sleep)
 */
mblk_t *
esballoca_wait(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	return (esballoca(base, size, pri, frp));
}

void
freemsg(mblk_t *mp)
{
	mblk_t *mp_cont;
	dblk_t *db;

	while (mp) {
		db = mp->b_datap;
		mp_cont = mp->b_cont;

		ASSERT(db->db_ref > 0);
		ASSERT(mp->b_next == NULL && mp->b_prev == NULL);

		db->db_free(mp, db);
		mp = mp_cont;
	}
}
