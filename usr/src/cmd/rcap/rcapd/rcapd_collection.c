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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "rcapd.h"
#include "utils.h"

/*
 * An abstract "collection" of processes.  Multiple types of collections can
 * exist, one of which is selected at run-time.  Currently, the only one
 * defined corresponds to project(5)s.
 */

#define	MAX(x, y) (((x) > (y)) ? (x) : (y))

typedef struct {
	rcid_t		*lfa_colidp;
	lcollection_t	*lfa_found;
} lcollection_find_arg_t;

extern void lcollection_update_project(lcollection_update_type_t,
    void(*)(char *, char *, int, uint64_t, int));
extern void lcollection_update_zone(lcollection_update_type_t,
    void(*)(char *, char *, int, uint64_t, int));
static void lcollection_update_notification_cb(char *, char *, int, uint64_t,
    int);

rcid_t(*rc_getidbypsinfo)(psinfo_t *);
uint64_t phys_total = 0;
static lcollection_t *lcollection_head = NULL;

void
lcollection_update(lcollection_update_type_t ut)
{
	lcollection_update_zone(ut, lcollection_update_notification_cb);
	lcollection_update_project(ut, lcollection_update_notification_cb);
}

/*
 * Inserts a collection with the supplied identity, or updates the caps of an
 * existing one.  The return value will have these bits set, depending on the
 * previous and new cap values.  If no cap was displaced, and the requested cap
 * is 0, no collection will be added, and the applicable *ZERO flags will be
 * set.
 *
 *	LCST_CAP_CHANGED
 *	LCST_CAP_REMOVED
 *	LCSS_CAP_ZERO
 */
lcollection_t *
lcollection_insert_update(rcid_t *colidp, uint64_t rss_cap, char *name,
    int *changes)
{
	lcollection_t *lcol;

	*changes = 0;

	if (rss_cap == 0)
		*changes |= LCST_CAP_ZERO;

	lcol = lcollection_find(colidp);

	/*
	 * If the specified collection is capped, add it to lcollection.
	 */
	if (lcol == NULL) {
		/*
		 * If the cap has been zeroed and the collection doesn't exist,
		 * don't create the collection just to remvoe the cap later.
		 */
		if (rss_cap == 0)
			return (NULL);

		*changes |= LCST_CAP_CHANGED;
		lcol = malloc(sizeof (*lcol));
		if (lcol == NULL) {
			debug("not enough memory to monitor %s %s",
			    (colidp->rcid_type == RCIDT_PROJECT ?
			    "project" : "zone"), name);
			return (NULL);
		}
		(void) bzero(lcol, sizeof (*lcol));

		lcol->lcol_id = *colidp;
		debug("added collection %s\n", name);
		lcol->lcol_prev = NULL;
		lcol->lcol_next = lcollection_head;
		lcol->lcol_stat.lcols_min_rss = (uint64_t)-1;
		if (lcollection_head != NULL)
			lcollection_head->lcol_prev = lcol;
		lcollection_head = lcol;
	}

	/*
	 * Set/update the collection's name.
	 */
	(void) strlcpy(lcol->lcol_name, name, sizeof (lcol->lcol_name));

	/*
	 * Set cap flags.
	 */
	if (rss_cap != lcol->lcol_rss_cap) {
		*changes |= LCST_CAP_CHANGED;
		lcol->lcol_rss_cap = rss_cap;
		if (lcol->lcol_rss_cap == 0)
			*changes |= LCST_CAP_REMOVED;
	}

	if (rss_cap > 0)
		lcol->lcol_mark++;

	return (lcol);
}

static void
lcollection_update_notification_cb(char *col_type, char *name, int changes,
    uint64_t rss_cap, int mark)
{
	/*
	 * Assume the collection has been updated redundantly if its mark count
	 * exceeds 1, and that another notification is unnecessary.
	 */
	if (mark > 1)
		return;

	if (changes & LCST_CAP_ZERO)
		debug("%s %s: %s\n", col_type, name,
		    (changes & LCST_CAP_REMOVED) ? "cap removed" : "uncapped");
	else
		debug("%s %s: cap: %llukB\n", col_type, name,
		    (unsigned long long)rss_cap);
}

/*
 * Function to walk list of collections and invoke the specified callback with
 * the specified argument.  Callbacks are allowed to change the linkage of the
 * collection on which they act.
 */
void
list_walk_collection(int (*cb)(lcollection_t *, void *), void *arg)
{
	lcollection_t *lcol;
	lcollection_t *next;

	lcol = lcollection_head;
	while (lcol != NULL) {
		next = lcol->lcol_next;
		if (cb(lcol, arg) != 0)
			return;
		lcol = next;
	}
}

/*
 * Returns a nonzero value if an lprocess_t is still a valid member of a given
 * collection.
 */
int
lcollection_member(lcollection_t *lcol, lprocess_t *lpc)
{
	lprocess_t *cur = lcol->lcol_lprocess;

	while (cur != NULL)
		if (cur == lpc)
			return (1);
		else
			cur = cur->lpc_next;
	return (0);
}

static int
lcollection_find_cb(lcollection_t *lcol, void *arg)
{
	rcid_t *colidp = ((lcollection_find_arg_t *)arg)->lfa_colidp;

	if (lcol->lcol_id.rcid_type == colidp->rcid_type &&
	    lcol->lcol_id.rcid_val == colidp->rcid_val) {
		((lcollection_find_arg_t *)arg)->lfa_found = lcol;
		return (1);
	}

	return (0);
}

lcollection_t *
lcollection_find(rcid_t *colidp)
{
	lcollection_find_arg_t lfa;

	lfa.lfa_colidp = colidp;
	lfa.lfa_found = NULL;
	list_walk_collection(lcollection_find_cb, &lfa);

	return (lfa.lfa_found);
}

/*
 * Unlinks a collection from lcollection.
 */
void
lcollection_free(lcollection_t *lcol)
{
	lprocess_t *lpc;
	lprocess_t *next;

	lpc = lcol->lcol_lprocess;
	while (lpc != NULL) {
		next = lpc->lpc_next;
		if (lpc->lpc_collection == lcol)
			lprocess_free(lpc);
		lpc = next;
	}

	/*
	 * Unlink the collection.
	 */
	if (lcol->lcol_prev != NULL)
		lcol->lcol_prev->lcol_next = lcol->lcol_next;
	if (lcol->lcol_next != NULL)
		lcol->lcol_next->lcol_prev = lcol->lcol_prev;
	if (lcollection_head == lcol)
		lcollection_head = lcol->lcol_next;
	lcol->lcol_next = lcol->lcol_prev = NULL;

	free(lcol);
}
