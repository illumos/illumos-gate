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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_conf.h>
#include <fmd_error.h>
#include <fmd_string.h>
#include <fmd_idspace.h>
#include <fmd.h>

static int
highbit(ulong_t i)
{
	int h = 1;

	if (i == 0)
		return (0);

#ifdef _LP64
	if (i & 0xffffffff00000000ul) {
		h += 32;
		i >>= 32;
	}
#endif

	if (i & 0xffff0000) {
		h += 16;
		i >>= 16;
	}

	if (i & 0xff00) {
		h += 8;
		i >>= 8;
	}

	if (i & 0xf0) {
		h += 4;
		i >>= 4;
	}

	if (i & 0xc) {
		h += 2;
		i >>= 2;
	}

	if (i & 0x2)
		h += 1;

	return (h);
}

fmd_idspace_t *
fmd_idspace_create(const char *name, id_t min, id_t max)
{
	fmd_idspace_t *ids = fmd_alloc(sizeof (fmd_idspace_t), FMD_SLEEP);
	uint_t ids_avg, ids_max, hashlen, hashmax;

	/*
	 * Dynamically size the hash table bucket array based on the desired
	 * chain length.  We hash by indexing on the low-order bits.
	 * Do not permit the hash bucket array to exceed a reasonable size.
	 */
	ASSERT(min >= 0 && max >= 0);
	ASSERT(max >= min);

	(void) fmd_conf_getprop(fmd.d_conf, "ids.avg", &ids_avg);
	(void) fmd_conf_getprop(fmd.d_conf, "ids.max", &ids_max);

	hashmax = max - min + 1;
	hashlen = 1 << highbit(hashmax / ids_avg);
	if (hashlen > ids_max)
		hashlen = ids_max;

	(void) strlcpy(ids->ids_name, name, sizeof (ids->ids_name));
	(void) pthread_mutex_init(&ids->ids_lock, NULL);
	(void) pthread_cond_init(&ids->ids_cv, NULL);

	ids->ids_hash = fmd_zalloc(sizeof (void *) * hashlen, FMD_SLEEP);
	ids->ids_hashlen = hashlen;
	ids->ids_refs = 0;
	ids->ids_nextid = min - 1;
	ids->ids_minid = min;
	ids->ids_maxid = max;
	ids->ids_count = 0;

	return (ids);
}

void
fmd_idspace_destroy(fmd_idspace_t *ids)
{
	fmd_idelem_t *ide, *nde;
	uint_t i;

	(void) pthread_mutex_lock(&ids->ids_lock);

	while (ids->ids_refs != 0)
		(void) pthread_cond_wait(&ids->ids_cv, &ids->ids_lock);

	for (i = 0; i < ids->ids_hashlen; i++) {
		for (ide = ids->ids_hash[i]; ide != NULL; ide = nde) {
			nde = ide->ide_next;
			fmd_free(ide, sizeof (fmd_idelem_t));
		}
	}

	fmd_free(ids->ids_hash, sizeof (void *) * ids->ids_hashlen);
	fmd_free(ids, sizeof (fmd_idspace_t));
}

void
fmd_idspace_apply(fmd_idspace_t *ids,
    void (*func)(fmd_idspace_t *, id_t, void *), void *arg)
{
	fmd_idelem_t *ide;
	id_t *ida, *idp;
	uint_t i, count;

	(void) pthread_mutex_lock(&ids->ids_lock);
	count = ids->ids_count;
	ida = idp = fmd_alloc(sizeof (id_t) * count, FMD_SLEEP);

	for (i = 0; i < ids->ids_hashlen; i++) {
		for (ide = ids->ids_hash[i]; ide != NULL; ide = ide->ide_next)
			*idp++ = ide->ide_id;
	}

	ASSERT(idp == ida + count);
	(void) pthread_mutex_unlock(&ids->ids_lock);

	for (i = 0; i < count; i++)
		func(ids, ida[i], arg);

	fmd_free(ida, sizeof (id_t) * count);
}

static fmd_idelem_t *
fmd_idspace_lookup(fmd_idspace_t *ids, id_t id)
{
	fmd_idelem_t *ide;

	ASSERT(MUTEX_HELD(&ids->ids_lock));
	ide = ids->ids_hash[id & (ids->ids_hashlen - 1)];

	for (; ide != NULL; ide = ide->ide_next) {
		if (ide->ide_id == id)
			break;
	}

	return (ide);
}

void *
fmd_idspace_getspecific(fmd_idspace_t *ids, id_t id)
{
	fmd_idelem_t *ide;
	void *data;

	(void) pthread_mutex_lock(&ids->ids_lock);
	ide = fmd_idspace_lookup(ids, id);
	data = ide ? ide->ide_data : NULL;
	(void) pthread_mutex_unlock(&ids->ids_lock);

	return (data);
}

void
fmd_idspace_setspecific(fmd_idspace_t *ids, id_t id, void *data)
{
	fmd_idelem_t *ide;

	(void) pthread_mutex_lock(&ids->ids_lock);

	while (ids->ids_refs != 0)
		(void) pthread_cond_wait(&ids->ids_cv, &ids->ids_lock);

	if ((ide = fmd_idspace_lookup(ids, id)) == NULL) {
		fmd_panic("idspace %p (%s) does not contain id %ld",
		    (void *)ids, ids->ids_name, id);
	}

	ide->ide_data = data;
	(void) pthread_mutex_unlock(&ids->ids_lock);
}

int
fmd_idspace_contains(fmd_idspace_t *ids, id_t id)
{
	fmd_idelem_t *ide;

	(void) pthread_mutex_lock(&ids->ids_lock);
	ide = fmd_idspace_lookup(ids, id);
	(void) pthread_mutex_unlock(&ids->ids_lock);

	return (ide != NULL);
}

int
fmd_idspace_valid(fmd_idspace_t *ids, id_t id)
{
	return (id >= ids->ids_minid && id <= ids->ids_maxid);
}

static id_t
fmd_idspace_xalloc_locked(fmd_idspace_t *ids, id_t id, void *data)
{
	fmd_idelem_t *ide;
	uint_t h;

	if (id < ids->ids_minid || id > ids->ids_maxid) {
		fmd_panic("%ld out of range [%ld .. %ld] for idspace %p (%s)\n",
		    id, ids->ids_minid, ids->ids_maxid,
		    (void *)ids, ids->ids_name);
	}

	if (fmd_idspace_lookup(ids, id) != NULL)
		return (fmd_set_errno(EALREADY));

	ide = fmd_alloc(sizeof (fmd_idelem_t), FMD_SLEEP);
	h = id & (ids->ids_hashlen - 1);

	ide->ide_next = ids->ids_hash[h];
	ide->ide_data = data;
	ide->ide_id = id;

	ids->ids_hash[h] = ide;
	ids->ids_count++;

	return (id);
}

id_t
fmd_idspace_xalloc(fmd_idspace_t *ids, id_t id, void *data)
{
	(void) pthread_mutex_lock(&ids->ids_lock);
	id = fmd_idspace_xalloc_locked(ids, id, data);
	(void) pthread_mutex_unlock(&ids->ids_lock);
	return (id);
}

static id_t
fmd_idspace_alloc_locked(fmd_idspace_t *ids, void *data)
{
	id_t id;

	ASSERT(MUTEX_HELD(&ids->ids_lock));

	if (ids->ids_count == ids->ids_maxid - ids->ids_minid + 1)
		return (fmd_set_errno(ENOSPC));

	do {
		if (++ids->ids_nextid > ids->ids_maxid)
			ids->ids_nextid = ids->ids_minid;
		id = ids->ids_nextid;
	} while (fmd_idspace_xalloc_locked(ids, id, data) != id);

	return (id);
}

id_t
fmd_idspace_alloc(fmd_idspace_t *ids, void *data)
{
	id_t id;

	(void) pthread_mutex_lock(&ids->ids_lock);
	id = fmd_idspace_alloc_locked(ids, data);
	(void) pthread_mutex_unlock(&ids->ids_lock);

	return (id);
}

/*
 * For the moment, we use a simple but slow implementation: reset ids_nextid to
 * the minimum id and search in order from there.  If this becomes performance
 * sensitive we can maintain a freelist of the unallocated identifiers, etc.
 */
id_t
fmd_idspace_alloc_min(fmd_idspace_t *ids, void *data)
{
	id_t id;

	(void) pthread_mutex_lock(&ids->ids_lock);
	ids->ids_nextid = ids->ids_minid - 1;
	id = fmd_idspace_alloc_locked(ids, data);
	(void) pthread_mutex_unlock(&ids->ids_lock);

	return (id);
}

void *
fmd_idspace_free(fmd_idspace_t *ids, id_t id)
{
	fmd_idelem_t *ide, **pp;
	void *data;

	(void) pthread_mutex_lock(&ids->ids_lock);
	pp = &ids->ids_hash[id & (ids->ids_hashlen - 1)];

	for (ide = *pp; ide != NULL; ide = ide->ide_next) {
		if (ide->ide_id != id)
			pp = &ide->ide_next;
		else
			break;
	}

	if (ide == NULL) {
		(void) pthread_mutex_unlock(&ids->ids_lock);
		return (NULL);
	}

	data = ide->ide_data;
	*pp = ide->ide_next;
	fmd_free(ide, sizeof (fmd_idelem_t));

	ASSERT(ids->ids_count != 0);
	ids->ids_count--;

	(void) pthread_mutex_unlock(&ids->ids_lock);
	return (data);
}

/*
 * Retrieve the id-specific data for the specified id and place a hold on the
 * id so that it cannot be or deleted until fmd_idspace_rele(ids, id) is
 * called.  For simplicity, we now use a single global reference count for all
 * holds.  If this feature needs to be used in a place where there is high
 * contention between holders and deleters, the implementation can be modified
 * to use either a per-hash-bucket or a per-id-element condition variable.
 */
void *
fmd_idspace_hold(fmd_idspace_t *ids, id_t id)
{
	fmd_idelem_t *ide;
	void *data = NULL;

	(void) pthread_mutex_lock(&ids->ids_lock);

	if ((ide = fmd_idspace_lookup(ids, id)) != NULL) {
		ids->ids_refs++;
		ASSERT(ids->ids_refs != 0);
		data = ide->ide_data;
		ASSERT(data != NULL);
	}

	(void) pthread_mutex_unlock(&ids->ids_lock);
	return (data);
}

void
fmd_idspace_rele(fmd_idspace_t *ids, id_t id)
{
	(void) pthread_mutex_lock(&ids->ids_lock);

	ASSERT(fmd_idspace_lookup(ids, id) != NULL);
	ASSERT(ids->ids_refs != 0);
	ids->ids_refs--;

	(void) pthread_cond_broadcast(&ids->ids_cv);
	(void) pthread_mutex_unlock(&ids->ids_lock);
}
