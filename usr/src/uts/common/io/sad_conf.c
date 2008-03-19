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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Config dependent data structures for the Streams Administrative Driver
 * (or "Ballad of the SAD Cafe").
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/sad.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>

/*
 * Currently we store all the sad data in a hash table keyed by major
 * number.  This is far from ideal.  It means that if a single device
 * starts using lots of SAP_ONE entries all its entries will hash
 * to the same bucket and we'll get very long chains for that bucket.
 *
 * Unfortunately, it's not possible to hash by a different key or to easily
 * break up our one hash into seperate hashs.  The reason is because
 * the hash contains mixed data types.  Ie, it has three different
 * types of autopush nodes in it:  SAP_ALL, SAP_RANGE, SAP_ONE.  Not
 * only does the hash table contain nodes of different types, but we
 * have to be able to search the table with a node of one type that
 * might match another node with a different type.  (ie, we might search
 * for a SAP_ONE node with a value that matches a SAP_ALL node in the
 * hash, or vice versa.)
 *
 * An ideal solution would probably be an AVL tree sorted by major
 * numbers.  Each node in the AVL tree would have the following optional
 * data associated with it:
 *	- a single SAP_ALL autopush node
 *	- an or avl tree or hash table of SAP_RANGE and SAP_ONE autopush
 *	  nodes indexed by minor numbers.  perhaps two separate tables,
 *	  one for each type of autopush nodes.
 *
 * Note that regardless of how the data is stored there can't be any overlap
 * stored between autopush nodes.  For example, if there is a SAP_ALL node
 * for a given major number then there can't be any SAP_RANGE or SAP_ONE
 * nodes for that same major number.
 */

/*
 * Private Internal Interfaces
 */
/*ARGSUSED*/
static uint_t
sad_hash_alg(void *hash_data, mod_hash_key_t key)
{
	struct apcommon *apc = (struct apcommon *)key;

	ASSERT(sad_apc_verify(apc) == 0);
	return (apc->apc_major);
}

/*
 * Compare hash keys based off of major, minor, lastminor, and type.
 */
static int
sad_hash_keycmp(mod_hash_key_t key1, mod_hash_key_t key2)
{
	struct apcommon *apc1 = (struct apcommon *)key1;
	struct apcommon *apc2 = (struct apcommon *)key2;

	ASSERT(sad_apc_verify(apc1) == 0);
	ASSERT(sad_apc_verify(apc2) == 0);

	/* Filter out cases where the major number doesn't match. */
	if (apc1->apc_major != apc2->apc_major)
		return (1);

	/* If either type is SAP_ALL then we're done. */
	if ((apc1->apc_cmd == SAP_ALL) || (apc2->apc_cmd == SAP_ALL))
		return (0);

	/* Deal with the case where both types are SAP_ONE. */
	if ((apc1->apc_cmd == SAP_ONE) && (apc2->apc_cmd == SAP_ONE)) {
		/* Check if the minor numbers match. */
		return (apc1->apc_minor != apc2->apc_minor);
	}

	/* Deal with the case where both types are SAP_RANGE. */
	if ((apc1->apc_cmd == SAP_RANGE) && (apc2->apc_cmd == SAP_RANGE)) {
		/* Check for overlapping ranges. */
		if ((apc1->apc_lastminor < apc2->apc_minor) ||
		    (apc1->apc_minor > apc2->apc_lastminor))
			return (1);
		return (0);
	}

	/*
	 * We know that one type is SAP_ONE and the other is SAP_RANGE.
	 * So now let's do range matching.
	 */
	if (apc1->apc_cmd == SAP_RANGE) {
		ASSERT(apc2->apc_cmd == SAP_ONE);
		if ((apc1->apc_lastminor < apc2->apc_minor) ||
		    (apc1->apc_minor > apc2->apc_minor))
			return (1);
	} else {
		ASSERT(apc1->apc_cmd == SAP_ONE);
		ASSERT(apc2->apc_cmd == SAP_RANGE);
		if ((apc1->apc_minor < apc2->apc_minor) ||
		    (apc1->apc_minor > apc2->apc_lastminor))
			return (1);
	}
	return (0);
}

/*ARGSUSED*/
static uint_t
sad_hash_free_value(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	struct autopush *ap = (struct autopush *)val;

	ASSERT(ap->ap_cnt > 0);
	if (--(ap->ap_cnt) == 0)
		kmem_free(ap, sizeof (struct autopush));

	return (MH_WALK_CONTINUE);
}

/*
 * External Interfaces
 */
int
sad_apc_verify(struct apcommon *apc)
{
	/* sanity check the number of modules to push */
	if ((apc->apc_npush == 0) || (apc->apc_npush > MAXAPUSH) ||
	    (apc->apc_npush > nstrpush))
		return (EINVAL);

	/* Check for NODEV major vaule */
	if (apc->apc_major == -1)
		return (EINVAL);

	switch (apc->apc_cmd) {
	case SAP_ALL:
	case SAP_ONE:
		/*
		 * Really, we'd like to be strict here and make sure that
		 * apc_lastminor is 0 (since setting apc_lastminor for
		 * SAP_ALL and SAP_ONE commands doesn't make any sense),
		 * but we can't since historically apc_lastminor has been
		 * silently ignored for non-SAP_RANGE commands.
		 */
		break;
	case SAP_RANGE:
		if (apc->apc_lastminor <= apc->apc_minor)
			return (ERANGE);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
sad_ap_verify(struct autopush *ap)
{
	int ret, i;

	if ((ret = sad_apc_verify(&ap->ap_common)) != 0)
		return (ret);

	/*
	 * Validate that the specified list of modules exist.  Note that
	 * ap_npush has already been sanity checked by sad_apc_verify().
	 */
	for (i = 0; i < ap->ap_npush; i++) {
		ap->ap_list[i][FMNAMESZ] = '\0';
		if (fmodsw_find(ap->ap_list[i], FMODSW_LOAD) == NULL)
			return (EINVAL);
	}
	return (0);
}

struct autopush *
sad_ap_alloc(void)
{
	struct autopush *ap_new;

	ap_new = kmem_zalloc(sizeof (struct autopush), KM_SLEEP);
	ap_new->ap_cnt = 1;
	return (ap_new);
}

void
sad_ap_rele(struct autopush *ap, str_stack_t *ss)
{
	mutex_enter(&ss->ss_sad_lock);
	ASSERT(ap->ap_cnt > 0);
	if (--(ap->ap_cnt) == 0) {
		mutex_exit(&ss->ss_sad_lock);
		kmem_free(ap, sizeof (struct autopush));
	} else {
		mutex_exit(&ss->ss_sad_lock);
	}
}

void
sad_ap_insert(struct autopush *ap, str_stack_t *ss)
{
	ASSERT(MUTEX_HELD(&ss->ss_sad_lock));
	ASSERT(sad_apc_verify(&ap->ap_common) == 0);
	ASSERT(sad_ap_find(&ap->ap_common, ss) == NULL);
	(void) mod_hash_insert(ss->ss_sad_hash, &ap->ap_common, ap);
}

void
sad_ap_remove(struct autopush *ap, str_stack_t *ss)
{
	struct autopush	*ap_removed = NULL;

	ASSERT(MUTEX_HELD(&ss->ss_sad_lock));
	(void) mod_hash_remove(ss->ss_sad_hash, &ap->ap_common,
	    (mod_hash_val_t *)&ap_removed);
	ASSERT(ap == ap_removed);
}

struct autopush *
sad_ap_find(struct apcommon *apc, str_stack_t *ss)
{
	struct autopush	*ap_result = NULL;

	ASSERT(MUTEX_HELD(&ss->ss_sad_lock));
	ASSERT(sad_apc_verify(apc) == 0);

	(void) mod_hash_find(ss->ss_sad_hash, apc,
	    (mod_hash_val_t *)&ap_result);
	if (ap_result != NULL)
		ap_result->ap_cnt++;
	return (ap_result);
}

struct autopush *
sad_ap_find_by_dev(dev_t dev, str_stack_t *ss)
{
	struct apcommon	apc;
	struct autopush	*ap_result;

	ASSERT(MUTEX_NOT_HELD(&ss->ss_sad_lock));

	/* prepare an apcommon structure to search with */
	apc.apc_cmd = SAP_ONE;
	apc.apc_major = getmajor(dev);
	apc.apc_minor = getminor(dev);

	/*
	 * the following values must be set but initialized to have a
	 * valid apcommon struct, but since we're only using this
	 * structure to do a query the values are never actually used.
	 */
	apc.apc_npush = 1;
	apc.apc_lastminor = 0;

	mutex_enter(&ss->ss_sad_lock);
	ap_result = sad_ap_find(&apc, ss);
	mutex_exit(&ss->ss_sad_lock);
	return (ap_result);
}

void
sad_initspace(str_stack_t *ss)
{
	mutex_init(&ss->ss_sad_lock, NULL, MUTEX_DEFAULT, NULL);
	ss->ss_sad_hash_nchains = 127;
	ss->ss_sadcnt = 16;

	ss->ss_saddev = kmem_zalloc(ss->ss_sadcnt * sizeof (struct saddev),
	    KM_SLEEP);
	ss->ss_sad_hash = mod_hash_create_extended("sad_hash",
	    ss->ss_sad_hash_nchains, mod_hash_null_keydtor,
	    mod_hash_null_valdtor,
	    sad_hash_alg, NULL, sad_hash_keycmp, KM_SLEEP);
}

void
sad_freespace(str_stack_t *ss)
{
	kmem_free(ss->ss_saddev, ss->ss_sadcnt * sizeof (struct saddev));
	ss->ss_saddev = NULL;

	mutex_enter(&ss->ss_sad_lock);
	mod_hash_walk(ss->ss_sad_hash, sad_hash_free_value, NULL);
	mod_hash_destroy_hash(ss->ss_sad_hash);
	ss->ss_sad_hash = NULL;
	mutex_exit(&ss->ss_sad_lock);

	mutex_destroy(&ss->ss_sad_lock);
}
