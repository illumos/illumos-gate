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

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/types.h>
#include <sys/mutex_impl.h>
#include <sys/rwlock_impl.h>
#include <sys/zone.h>
#include <sys/socket.h>

#include "nfssrv.h"
#include "common.h"

struct common_zsd_cb_data {
	zone_key_t	key;		/* Key of ZSD for which we're looking */
	uint_t		found;		/* Was the specific ZSD entry found? */
	uintptr_t	zsd_data;	/* Result */
};

int
zoned_find_zsd_cb(uintptr_t addr, const void *data, void *cb_data)
{
	const struct zsd_entry *entry = data;
	struct common_zsd_cb_data *cbd = cb_data;

	if (cbd->key != entry->zsd_key)
		return (WALK_NEXT);

	/* Match */
	cbd->zsd_data = (uintptr_t)entry->zsd_data;
	cbd->found = TRUE;
	return (WALK_DONE);
}

int
zoned_get_nfs_globals(uintptr_t zonep, uintptr_t *result)
{
	return (zoned_get_zsd(zonep, "nfssrv_zone_key", result));
}

int
zoned_get_zsd(uintptr_t zonep, char *key_str, uintptr_t *result)
{
	zone_key_t	key;
	struct		common_zsd_cb_data cbd;

	if (mdb_readsym(&key, sizeof (zone_key_t), key_str) == -1) {
		mdb_warn("failed to get %s", key_str);
		return (DCMD_ERR);
	}

	cbd.key = key;
	cbd.found = FALSE;

	if (mdb_pwalk("zsd", zoned_find_zsd_cb, &cbd, zonep) != 0) {
		mdb_warn("failed to walk zsd");
		return (DCMD_ERR);
	}

	if (cbd.found == FALSE) {
		mdb_warn("no ZSD entry found");
		return (DCMD_ERR);
	}

	*result = cbd.zsd_data;
	return (DCMD_OK);
}


const char *
common_mutex(kmutex_t *mp)
{
	char *s;
	size_t sz;
	mutex_impl_t *lp = (mutex_impl_t *)mp;

	if (MUTEX_TYPE_SPIN(lp)) {
		const char *fmt = "spin - lock(%x)/oldspl(%x)/minspl(%x)";

		sz = 1 + mdb_snprintf(NULL, 0, fmt, lp->m_spin.m_spinlock,
		    lp->m_spin.m_oldspl, lp->m_spin.m_minspl);
		s = mdb_alloc(sz, UM_SLEEP | UM_GC);
		(void) mdb_snprintf(s, sz, fmt, lp->m_spin.m_spinlock,
		    lp->m_spin.m_oldspl, lp->m_spin.m_minspl);

		return (s);
	}

	if (MUTEX_TYPE_ADAPTIVE(lp)) {
		const char *fmt = "adaptive - owner %p%s";

		if ((MUTEX_OWNER(lp) == NULL) && !MUTEX_HAS_WAITERS(lp))
			return ("mutex not held");

		sz = 1 + mdb_snprintf(NULL, 0, fmt, MUTEX_OWNER(lp),
		    MUTEX_HAS_WAITERS(lp) ? " has waiters" : "");
		s = mdb_alloc(sz, UM_SLEEP | UM_GC);
		(void) mdb_snprintf(s, sz, fmt, MUTEX_OWNER(lp),
		    MUTEX_HAS_WAITERS(lp) ? " has waiters" : "");

		return (s);
	}

	return ("mutex dead");
}

const char *
common_rwlock(krwlock_t *lp)
{
	char *s;
	size_t sz;
	uintptr_t w = ((rwlock_impl_t *)lp)->rw_wwwh;
	uintptr_t o = w & RW_OWNER;
	const char *hw = (w & RW_HAS_WAITERS) ? " has_waiters" : "";
	const char *ww = (w & RW_WRITE_WANTED) ? " write_wanted" : "";
	const char *wl = (w & RW_WRITE_LOCKED) ? " write_locked" : "";

	sz = 1 + mdb_snprintf(NULL, 0, "owner %p%s%s%s", o, hw, ww, wl);
	s = mdb_alloc(sz, UM_SLEEP | UM_GC);
	(void) mdb_snprintf(s, sz, "owner %p%s%s%s", o, hw, ww, wl);

	return (s);
}

const char *
common_netbuf_str(struct netbuf *nb)
{
	struct sockaddr_in *in;

	in = mdb_alloc(nb->len + 1, UM_SLEEP | UM_GC);
	if (mdb_vread(in, nb->len, (uintptr_t)nb->buf) == -1)
		return ("");

	if (nb->len < sizeof (struct sockaddr_in)) {
		((char *)in)[nb->len] = '\0';
		return ((char *)in);
	}

	if (in->sin_family == AF_INET) {
		char *s;
		ssize_t sz;

		mdb_nhconvert(&in->sin_port, &in->sin_port,
		    sizeof (in->sin_port));

		sz = 1 + mdb_snprintf(NULL, 0, "%I:%d", in->sin_addr.s_addr,
		    in->sin_port);
		s = mdb_alloc(sz, UM_SLEEP | UM_GC);
		(void) mdb_snprintf(s, sz, "%I:%d", in->sin_addr.s_addr,
		    in->sin_port);

		return (s);
	} else if ((in->sin_family == AF_INET6) &&
	    (nb->len >= sizeof (struct sockaddr_in6))) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)in;
		char *s;
		size_t sz;

		mdb_nhconvert(&in6->sin6_port, &in6->sin6_port,
		    sizeof (in6->sin6_port));

		sz = 1 + mdb_snprintf(NULL, 0, "[%N]:%d",
		    in6->sin6_addr.s6_addr, in6->sin6_port);
		s = mdb_alloc(sz, UM_SLEEP | UM_GC);
		(void) mdb_snprintf(s, sz, "[%N]:%d", in6->sin6_addr.s6_addr,
		    in6->sin6_port);

		return (s);
	} else {
		((char *)in)[nb->len] = '\0';
		return ((char *)in);
	}
}

/*
 * Generic hash table walker
 *
 */

typedef struct hash_table_walk_data {
	uintptr_t table;	/* current table pointer */
	int count;		/* number of entries to process */
	void *member;		/* copy of the current member structure */
} hash_table_walk_data_t;

int
hash_table_walk_init(mdb_walk_state_t *wsp)
{
	hash_table_walk_arg_t *arg = wsp->walk_arg;
	hash_table_walk_data_t *wd = mdb_alloc(sizeof (*wd), UM_SLEEP);

	wd->table = arg->array_addr;
	wd->count = arg->array_len;

	wd->member = mdb_alloc(arg->member_size, UM_SLEEP);

	wsp->walk_addr = 0;
	wsp->walk_data = wd;

	return (WALK_NEXT);
}

int
hash_table_walk_step(mdb_walk_state_t *wsp)
{
	hash_table_walk_arg_t *arg = wsp->walk_arg;
	hash_table_walk_data_t *wd = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr;

	if (wd->count == 0)
		return (WALK_DONE);

	if (addr == 0) {
		if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
		    wd->table + arg->first_offset) == -1) {
			mdb_warn("can't read %s", arg->first_name);
			return (WALK_ERR);
		}
		if (wsp->walk_addr == 0)
			wsp->walk_addr = wd->table;

		return (WALK_NEXT);
	}

	if (addr == wd->table) {
		wd->count--;
		wd->table += arg->head_size;
		wsp->walk_addr = 0;

		return (WALK_NEXT);
	}

	if (mdb_vread(wd->member, arg->member_size, addr) == -1) {
		mdb_warn("unable to read %s", arg->member_type_name);
		return (WALK_ERR);
	}

	wsp->walk_addr = *(uintptr_t *)((uintptr_t)wd->member
	    + arg->next_offset);
	if (wsp->walk_addr == 0)
		wsp->walk_addr = wd->table;

	return (wsp->walk_callback(addr, wd->member, wsp->walk_cbdata));
}

void
hash_table_walk_fini(mdb_walk_state_t *wsp)
{
	hash_table_walk_arg_t *arg = wsp->walk_arg;
	hash_table_walk_data_t *wd = wsp->walk_data;

	mdb_free(wd->member, arg->member_size);
	mdb_free(wd, sizeof (*wd));
}
