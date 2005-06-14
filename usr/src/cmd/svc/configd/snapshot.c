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

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <strings.h>
#include "configd.h"
#include "repcache_protocol.h"

typedef struct snapshot_bucket {
	pthread_mutex_t	sb_lock;
	rc_snapshot_t	*sb_head;

	char		sb_pad[64 - sizeof (pthread_mutex_t) -
			    sizeof (rc_snapshot_t *)];
} snapshot_bucket_t;

#define	SN_HASH_SIZE	64
#define	SN_HASH_MASK	(SN_HASH_SIZE - 1)

#pragma align 64(snapshot_hash)
static snapshot_bucket_t snapshot_hash[SN_HASH_SIZE];

#define	SNAPSHOT_BUCKET(h)	(&snapshot_hash[(h) & SN_HASH_MASK])

static rc_snapshot_t *
snapshot_alloc(void)
{
	rc_snapshot_t *sp;
	sp = uu_zalloc(sizeof (*sp));

	(void) pthread_mutex_init(&sp->rs_lock, NULL);
	(void) pthread_cond_init(&sp->rs_cv, NULL);

	sp->rs_refcnt++;
	return (sp);
}

static void
snapshot_free(rc_snapshot_t *sp)
{
	rc_snaplevel_t *lvl, *next;

	assert(sp->rs_refcnt == 0 && sp->rs_childref == 0);

	(void) pthread_mutex_destroy(&sp->rs_lock);
	(void) pthread_cond_destroy(&sp->rs_cv);

	for (lvl = sp->rs_levels; lvl != NULL; lvl = next) {
		next = lvl->rsl_next;

		assert(lvl->rsl_parent == sp);
		lvl->rsl_parent = NULL;

		if (lvl->rsl_service)
			free((char *)lvl->rsl_service);
		if (lvl->rsl_instance)
			free((char *)lvl->rsl_instance);

		uu_free(lvl);
	}
	uu_free(sp);
}

static void
rc_snapshot_hold(rc_snapshot_t *sp)
{
	(void) pthread_mutex_lock(&sp->rs_lock);
	sp->rs_refcnt++;
	assert(sp->rs_refcnt > 0);
	(void) pthread_mutex_unlock(&sp->rs_lock);
}

void
rc_snapshot_rele(rc_snapshot_t *sp)
{
	int done;
	(void) pthread_mutex_lock(&sp->rs_lock);
	assert(sp->rs_refcnt > 0);
	sp->rs_refcnt--;
	done = ((sp->rs_flags & RC_SNAPSHOT_DEAD) &&
	    sp->rs_refcnt == 0 && sp->rs_childref == 0);
	(void) pthread_mutex_unlock(&sp->rs_lock);

	if (done)
		snapshot_free(sp);
}

void
rc_snaplevel_hold(rc_snaplevel_t *lvl)
{
	rc_snapshot_t *sp = lvl->rsl_parent;
	(void) pthread_mutex_lock(&sp->rs_lock);
	sp->rs_childref++;
	assert(sp->rs_childref > 0);
	(void) pthread_mutex_unlock(&sp->rs_lock);
}

void
rc_snaplevel_rele(rc_snaplevel_t *lvl)
{
	int done;
	rc_snapshot_t *sp = lvl->rsl_parent;
	(void) pthread_mutex_lock(&sp->rs_lock);
	assert(sp->rs_childref > 0);
	sp->rs_childref--;
	done = ((sp->rs_flags & RC_SNAPSHOT_DEAD) &&
	    sp->rs_refcnt == 0 && sp->rs_childref == 0);
	(void) pthread_mutex_unlock(&sp->rs_lock);

	if (done)
		snapshot_free(sp);
}

static snapshot_bucket_t *
snapshot_hold_bucket(uint32_t snap_id)
{
	snapshot_bucket_t *bp = SNAPSHOT_BUCKET(snap_id);
	(void) pthread_mutex_lock(&bp->sb_lock);
	return (bp);
}

static void
snapshot_rele_bucket(snapshot_bucket_t *bp)
{
	assert(MUTEX_HELD(&bp->sb_lock));
	(void) pthread_mutex_unlock(&bp->sb_lock);
}

static rc_snapshot_t *
snapshot_lookup_unlocked(snapshot_bucket_t *bp, uint32_t snap_id)
{
	rc_snapshot_t *sp;

	assert(MUTEX_HELD(&bp->sb_lock));
	assert(bp == SNAPSHOT_BUCKET(snap_id));

	for (sp = bp->sb_head; sp != NULL; sp = sp->rs_hash_next) {
		if (sp->rs_snap_id == snap_id) {
			rc_snapshot_hold(sp);
			return (sp);
		}
	}
	return (NULL);
}

static void
snapshot_insert_unlocked(snapshot_bucket_t *bp, rc_snapshot_t *sp)
{
	assert(MUTEX_HELD(&bp->sb_lock));
	assert(bp == SNAPSHOT_BUCKET(sp->rs_snap_id));

	assert(sp->rs_hash_next == NULL);

	sp->rs_hash_next = bp->sb_head;
	bp->sb_head = sp;
}

static void
snapshot_remove_unlocked(snapshot_bucket_t *bp, rc_snapshot_t *sp)
{
	rc_snapshot_t **spp;

	assert(MUTEX_HELD(&bp->sb_lock));
	assert(bp == SNAPSHOT_BUCKET(sp->rs_snap_id));

	assert(sp->rs_hash_next == NULL);

	for (spp = &bp->sb_head; *spp != NULL; spp = &(*spp)->rs_hash_next)
		if (*spp == sp)
			break;

	assert(*spp == sp);
	*spp = sp->rs_hash_next;
	sp->rs_hash_next = NULL;
}

/*
 * Look up the snapshot with id snap_id in the hash table, or create it
 * & populate it with its snaplevels if it's not in the hash table yet.
 *
 * Fails with
 *   _NO_RESOURCES
 */
int
rc_snapshot_get(uint32_t snap_id, rc_snapshot_t **snpp)
{
	snapshot_bucket_t *bp;
	rc_snapshot_t *sp;
	int r;

	bp = snapshot_hold_bucket(snap_id);
	sp = snapshot_lookup_unlocked(bp, snap_id);
	if (sp != NULL) {
		snapshot_rele_bucket(bp);
		(void) pthread_mutex_lock(&sp->rs_lock);
		while (sp->rs_flags & RC_SNAPSHOT_FILLING)
			(void) pthread_cond_wait(&sp->rs_cv, &sp->rs_lock);

		if (sp->rs_flags & RC_SNAPSHOT_DEAD) {
			(void) pthread_mutex_unlock(&sp->rs_lock);
			rc_snapshot_rele(sp);
			return (REP_PROTOCOL_FAIL_NO_RESOURCES);
		}
		assert(sp->rs_flags & RC_SNAPSHOT_READY);
		(void) pthread_mutex_unlock(&sp->rs_lock);
		*snpp = sp;
		return (REP_PROTOCOL_SUCCESS);
	}
	sp = snapshot_alloc();
	sp->rs_snap_id = snap_id;
	sp->rs_flags |= RC_SNAPSHOT_FILLING;
	snapshot_insert_unlocked(bp, sp);
	snapshot_rele_bucket(bp);

	/*
	 * Now fill in the snapshot tree
	 */
	r = object_fill_snapshot(sp);
	if (r != REP_PROTOCOL_SUCCESS) {
		assert(r == REP_PROTOCOL_FAIL_NO_RESOURCES);

		/*
		 * failed -- first remove it from the hash table, then kill it
		 */
		bp = snapshot_hold_bucket(snap_id);
		snapshot_remove_unlocked(bp, sp);
		snapshot_rele_bucket(bp);

		(void) pthread_mutex_lock(&sp->rs_lock);
		sp->rs_flags &= ~RC_SNAPSHOT_FILLING;
		sp->rs_flags |= RC_SNAPSHOT_DEAD;
		(void) pthread_cond_broadcast(&sp->rs_cv);
		(void) pthread_mutex_unlock(&sp->rs_lock);
		rc_snapshot_rele(sp);		/* may free sp */
		return (r);
	}
	(void) pthread_mutex_lock(&sp->rs_lock);
	sp->rs_flags &= ~RC_SNAPSHOT_FILLING;
	sp->rs_flags |= RC_SNAPSHOT_READY;
	(void) pthread_cond_broadcast(&sp->rs_cv);
	(void) pthread_mutex_unlock(&sp->rs_lock);
	*snpp = sp;
	return (REP_PROTOCOL_SUCCESS);		/* pass on creation reference */
}
