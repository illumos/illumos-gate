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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/modctl.h>
#include <sys/hook_impl.h>
#include <sys/sdt.h>

/*
 * This file provides kernel hook framework.
 */

static struct modldrv modlmisc = {
	&mod_miscops,				/* drv_modops */
	"Hooks Interface v1.0",			/* drv_linkinfo */
};

static struct modlinkage modlinkage = {
	MODREV_1,				/* ml_rev */
	&modlmisc,				/* ml_linkage */
	NULL
};

/*
 * Hook internal functions
 */
static hook_int_t *hook_copy(hook_t *src);
static hook_event_int_t *hook_event_checkdup(hook_event_t *he);
static hook_event_int_t *hook_event_copy(hook_event_t *src);
static hook_event_int_t *hook_event_find(hook_family_int_t *hfi, char *event);
static void hook_event_free(hook_event_int_t *hei);
static hook_family_int_t *hook_family_copy(hook_family_t *src);
static hook_family_int_t *hook_family_find(char *family);
static void hook_family_free(hook_family_int_t *hfi);
static hook_int_t *hook_find(hook_event_int_t *hei, hook_t *h);
static void hook_free(hook_int_t *hi);
static void hook_init(void);

static cvwaitlock_t familylock;			/* global lock */
static hook_family_int_head_t familylist;	/* family list head */

/*
 * Module entry points.
 */
int
_init(void)
{
	hook_init();
	return (mod_install(&modlinkage));
}


int
_fini(void)
{
	return (mod_remove(&modlinkage));
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Function:	hook_init
 * Returns:	None
 * Parameters:	None
 *
 * Initialize hooks
 */
static void
hook_init(void)
{
	CVW_INIT(&familylock);
	SLIST_INIT(&familylist);
}


/*
 * Function:	hook_run
 * Returns:	int - return value according to callback func
 * Parameters:	token(I) - event pointer
 *		info(I) - message
 *
 * Run hooks for specific provider.  The hooks registered are stepped through
 * until either the end of the list is reached or a hook function returns a
 * non-zero value.  If a non-zero value is returned from a hook function, we
 * return that value back to our caller.  By design, a hook function can be
 * called more than once, simultaneously.
 */
int
hook_run(hook_event_token_t token, hook_data_t info)
{
	hook_int_t *hi;
	hook_event_int_t *hei;
	int rval = 0;

	ASSERT(token != NULL);

	hei = (hook_event_int_t *)token;
	DTRACE_PROBE2(hook__run__start,
	    hook_event_token_t, token,
	    hook_data_t, info);

	/* Hold global read lock to ensure event will not be deleted */
	CVW_ENTER_READ(&familylock);

	/* Hold event read lock to ensure hook will not be changed */
	CVW_ENTER_READ(&hei->hei_lock);

	TAILQ_FOREACH(hi, &hei->hei_head, hi_entry) {
		ASSERT(hi->hi_hook.h_func != NULL);
		DTRACE_PROBE3(hook__func__start,
		    hook_event_token_t, token,
		    hook_data_t, info,
		    hook_int_t *, hi);
		rval = (*hi->hi_hook.h_func)(token, info);
		DTRACE_PROBE4(hook__func__end,
		    hook_event_token_t, token,
		    hook_data_t, info,
		    hook_int_t *, hi,
		    int, rval);
		if (rval != 0)
			break;
	}

	CVW_EXIT_READ(&hei->hei_lock);
	CVW_EXIT_READ(&familylock);

	DTRACE_PROBE3(hook__run__end,
	    hook_event_token_t, token,
	    hook_data_t, info,
	    hook_int_t *, hi);

	return (rval);
}


/*
 * Function:	hook_family_add
 * Returns:	internal family pointer - NULL = Fail
 * Parameters:	hf(I) - family pointer
 *
 * Add new family to family list
 */
hook_family_int_t *
hook_family_add(hook_family_t *hf)
{
	hook_family_int_t *hfi, *new;

	ASSERT(hf != NULL);
	ASSERT(hf->hf_name != NULL);

	new = hook_family_copy(hf);
	if (new == NULL)
		return (NULL);

	CVW_ENTER_WRITE(&familylock);

	/* search family list */
	hfi = hook_family_find(hf->hf_name);
	if (hfi != NULL) {
		CVW_EXIT_WRITE(&familylock);
		hook_family_free(new);
		return (NULL);
	}

	/* Add to family list head */
	SLIST_INSERT_HEAD(&familylist, new, hfi_entry);

	CVW_EXIT_WRITE(&familylock);
	return (new);
}


/*
 * Function:	hook_family_remove
 * Returns:	int - 0 = Succ, Else = Fail
 * Parameters:	hfi(I) - internal family pointer
 *
 * Remove family from family list
 */
int
hook_family_remove(hook_family_int_t *hfi)
{

	ASSERT(hfi != NULL);

	CVW_ENTER_WRITE(&familylock);

	/* Check if there are events  */
	if (!SLIST_EMPTY(&hfi->hfi_head)) {
		CVW_EXIT_WRITE(&familylock);
		return (EBUSY);
	}

	/* Remove from family list */
	SLIST_REMOVE(&familylist, hfi, hook_family_int, hfi_entry);

	CVW_EXIT_WRITE(&familylock);
	hook_family_free(hfi);

	return (0);
}


/*
 * Function:	hook_family_copy
 * Returns:	internal family pointer - NULL = Failed
 * Parameters:	src(I) - family pointer
 *
 * Allocate internal family block and duplicate incoming family
 * No locks should be held across this function as it may sleep.
 */
static hook_family_int_t *
hook_family_copy(hook_family_t *src)
{
	hook_family_int_t *new;
	hook_family_t *dst;

	ASSERT(src != NULL);
	ASSERT(src->hf_name != NULL);

	new = (hook_family_int_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	/* Copy body */
	SLIST_INIT(&new->hfi_head);
	dst = &new->hfi_family;
	*dst = *src;

	/* Copy name */
	dst->hf_name = (char *)kmem_alloc(strlen(src->hf_name) + 1, KM_SLEEP);
	(void) strcpy(dst->hf_name, src->hf_name);

	return (new);
}


/*
 * Function:	hook_family_find
 * Returns:	internal family pointer - NULL = Not match
 * Parameters:	family(I) - family name string
 *
 * Search family list with family name
 * 	A lock on familylock must be held when called.
 */
static hook_family_int_t *
hook_family_find(char *family)
{
	hook_family_int_t *hfi = NULL;

	ASSERT(family != NULL);

	SLIST_FOREACH(hfi, &familylist, hfi_entry) {
		if (strcmp(hfi->hfi_family.hf_name, family) == 0)
			break;
	}
	return (hfi);
}


/*
 * Function:	hook_family_free
 * Returns:	None
 * Parameters:	hfi(I) - internal family pointer
 *
 * Free alloc memory for family
 */
static void
hook_family_free(hook_family_int_t *hfi)
{
	ASSERT(hfi != NULL);

	/* Free name space */
	if (hfi->hfi_family.hf_name != NULL) {
		kmem_free(hfi->hfi_family.hf_name,
		    strlen(hfi->hfi_family.hf_name) + 1);
	}

	/* Free container */
	kmem_free(hfi, sizeof (*hfi));
}


/*
 * Function:	hook_event_add
 * Returns:	internal event pointer - NULL = Fail
 * Parameters:	hfi(I) - internal family pointer
 *		he(I) - event pointer
 *
 * Add new event to event list on specific family.
 * This function can fail to return successfully if (1) it cannot allocate
 * enough memory for its own internal data structures, (2) the event has
 * already been registered (for any hook family.)
 */
hook_event_int_t *
hook_event_add(hook_family_int_t *hfi, hook_event_t *he)
{
	hook_event_int_t *hei, *new;

	ASSERT(hfi != NULL);
	ASSERT(he != NULL);
	ASSERT(he->he_name != NULL);

	new = hook_event_copy(he);
	if (new == NULL)
		return (NULL);

	CVW_ENTER_WRITE(&familylock);

	/* Check whether this event pointer is already registered */
	hei = hook_event_checkdup(he);
	if (hei != NULL) {
		CVW_EXIT_WRITE(&familylock);
		hook_event_free(new);
		return (NULL);
	}

	/* Add to event list head */
	SLIST_INSERT_HEAD(&hfi->hfi_head, new, hei_entry);

	CVW_EXIT_WRITE(&familylock);
	return (new);
}


/*
 * Function:	hook_event_remove
 * Returns:	int - 0 = Succ, Else = Fail
 * Parameters:	hfi(I) - internal family pointer
 *		he(I) - event pointer
 *
 * Remove event from event list on specific family
 */
int
hook_event_remove(hook_family_int_t *hfi, hook_event_t *he)
{
	hook_event_int_t *hei;

	ASSERT(hfi != NULL);
	ASSERT(he != NULL);

	CVW_ENTER_WRITE(&familylock);

	hei = hook_event_find(hfi, he->he_name);
	if (hei == NULL) {
		CVW_EXIT_WRITE(&familylock);
		return (ENXIO);
	}

	/* Check if there are registered hooks for this event */
	if (!TAILQ_EMPTY(&hei->hei_head)) {
		CVW_EXIT_WRITE(&familylock);
		return (EBUSY);
	}

	/* Remove from event list */
	SLIST_REMOVE(&hfi->hfi_head, hei, hook_event_int, hei_entry);

	CVW_EXIT_WRITE(&familylock);
	hook_event_free(hei);

	return (0);
}


/*
 * Function:    hook_event_checkdup
 * Returns:     internal event pointer - NULL = Not match
 * Parameters:  he(I) - event pointer
 *
 * Search whole list with event pointer
 *      A lock on familylock must be held when called.
 */
static hook_event_int_t *
hook_event_checkdup(hook_event_t *he)
{
	hook_family_int_t *hfi;
	hook_event_int_t *hei;

	ASSERT(he != NULL);

	SLIST_FOREACH(hfi, &familylist, hfi_entry) {
		SLIST_FOREACH(hei, &hfi->hfi_head, hei_entry) {
			if (hei->hei_event == he)
				return (hei);
		}
	}

	return (NULL);
}


/*
 * Function:	hook_event_copy
 * Returns:	internal event pointer - NULL = Failed
 * Parameters:	src(I) - event pointer
 *
 * Allocate internal event block and duplicate incoming event
 * No locks should be held across this function as it may sleep.
 */
static hook_event_int_t *
hook_event_copy(hook_event_t *src)
{
	hook_event_int_t *new;

	ASSERT(src != NULL);
	ASSERT(src->he_name != NULL);

	new = (hook_event_int_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	/* Copy body */
	TAILQ_INIT(&new->hei_head);
	new->hei_event = src;

	return (new);
}


/*
 * Function:	hook_event_find
 * Returns:	internal event pointer - NULL = Not match
 * Parameters:	hfi(I) - internal family pointer
 *		event(I) - event name string
 *
 * Search event list with event name
 * 	A lock on familylock must be held when called.
 */
static hook_event_int_t *
hook_event_find(hook_family_int_t *hfi, char *event)
{
	hook_event_int_t *hei = NULL;

	ASSERT(hfi != NULL);
	ASSERT(event != NULL);

	SLIST_FOREACH(hei, &hfi->hfi_head, hei_entry) {
		if (strcmp(hei->hei_event->he_name, event) == 0)
			break;
	}
	return (hei);
}


/*
 * Function:	hook_event_free
 * Returns:	None
 * Parameters:	hei(I) - internal event pointer
 *
 * Free alloc memory for event
 */
static void
hook_event_free(hook_event_int_t *hei)
{
	ASSERT(hei != NULL);

	/* Free container */
	kmem_free(hei, sizeof (*hei));
}


/*
 * Function:	hook_register
 * Returns:	int- 0 = Succ, Else = Fail
 * Parameters:	hfi(I) - internal family pointer
 *		event(I) - event name string
 *		h(I) - hook pointer
 *
 * Add new hook to hook list on spefic family, event
 */
int
hook_register(hook_family_int_t *hfi, char *event, hook_t *h)
{
	hook_event_int_t *hei;
	hook_int_t *hi, *new;

	ASSERT(hfi != NULL);
	ASSERT(event != NULL);
	ASSERT(h != NULL);

	/* Alloc hook_int_t and copy hook */
	new = hook_copy(h);
	if (new == NULL)
		return (ENOMEM);

	/*
	 * Since hook add/remove only impact event, so it is unnecessary
	 * to hold global family write lock. Just get read lock here to
	 * ensure event will not be removed when doing hooks operation
	 */
	CVW_ENTER_READ(&familylock);

	hei = hook_event_find(hfi, event);
	if (hei == NULL) {
		CVW_EXIT_READ(&familylock);
		hook_free(new);
		return (ENXIO);
	}

	CVW_ENTER_WRITE(&hei->hei_lock);

	/* Multiple hooks are only allowed for read-only events. */
	if (((hei->hei_event->he_flags & HOOK_RDONLY) == 0) &&
	    (!TAILQ_EMPTY(&hei->hei_head))) {
		CVW_EXIT_WRITE(&hei->hei_lock);
		CVW_EXIT_READ(&familylock);
		hook_free(new);
		return (EEXIST);
	}

	hi = hook_find(hei, h);
	if (hi != NULL) {
		CVW_EXIT_WRITE(&hei->hei_lock);
		CVW_EXIT_READ(&familylock);
		hook_free(new);
		return (EEXIST);
	}

	/* Add to hook list head */
	TAILQ_INSERT_HEAD(&hei->hei_head, new, hi_entry);
	hei->hei_event->he_interested = B_TRUE;

	CVW_EXIT_WRITE(&hei->hei_lock);
	CVW_EXIT_READ(&familylock);
	return (0);
}


/*
 * Function:	hook_unregister
 * Returns:	int - 0 = Succ, Else = Fail
 * Parameters:	hfi(I) - internal family pointer
 *		event(I) - event name string
 *		h(I) - hook pointer
 *
 * Remove hook from hook list on specific family, event
 */
int
hook_unregister(hook_family_int_t *hfi, char *event, hook_t *h)
{
	hook_event_int_t *hei;
	hook_int_t *hi;

	ASSERT(hfi != NULL);
	ASSERT(h != NULL);

	CVW_ENTER_READ(&familylock);

	hei = hook_event_find(hfi, event);
	if (hei == NULL) {
		CVW_EXIT_READ(&familylock);
		return (ENXIO);
	}

	/* Hold write lock for event */
	CVW_ENTER_WRITE(&hei->hei_lock);

	hi = hook_find(hei, h);
	if (hi == NULL) {
		CVW_EXIT_WRITE(&hei->hei_lock);
		CVW_EXIT_READ(&familylock);
		return (ENXIO);
	}

	/* Remove from hook list */
	TAILQ_REMOVE(&hei->hei_head, hi, hi_entry);
	if (TAILQ_EMPTY(&hei->hei_head)) {
		hei->hei_event->he_interested = B_FALSE;
	}

	CVW_EXIT_WRITE(&hei->hei_lock);
	CVW_EXIT_READ(&familylock);

	hook_free(hi);
	return (0);
}


/*
 * Function:	hook_find
 * Returns:	internal hook pointer - NULL = Not match
 * Parameters:	hei(I) - internal event pointer
 *		h(I) - hook pointer
 *
 * Search hook list
 * 	A lock on familylock must be held when called.
 */
static hook_int_t *
hook_find(hook_event_int_t *hei, hook_t *h)
{
	hook_int_t *hi;

	ASSERT(hei != NULL);
	ASSERT(h != NULL);

	TAILQ_FOREACH(hi, &hei->hei_head, hi_entry) {
		if (strcmp(hi->hi_hook.h_name, h->h_name) == 0)
			break;
	}
	return (hi);
}


/*
 * Function:	hook_copy
 * Returns:	internal hook pointer - NULL = Failed
 * Parameters:	src(I) - hook pointer
 *
 * Allocate internal hook block and duplicate incoming hook.
 * No locks should be held across this function as it may sleep.
 */
static hook_int_t *
hook_copy(hook_t *src)
{
	hook_int_t *new;
	hook_t *dst;

	ASSERT(src != NULL);
	ASSERT(src->h_name != NULL);

	new = (hook_int_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	/* Copy body */
	dst = &new->hi_hook;
	*dst = *src;

	/* Copy name */
	dst->h_name = (char *)kmem_alloc(strlen(src->h_name) + 1, KM_SLEEP);
	(void) strcpy(dst->h_name, src->h_name);

	return (new);
}

/*
 * Function:	hook_free
 * Returns:	None
 * Parameters:	hi(I) - internal hook pointer
 *
 * Free alloc memory for hook
 */
static void
hook_free(hook_int_t *hi)
{
	ASSERT(hi != NULL);

	/* Free name space */
	if (hi->hi_hook.h_name != NULL) {
		kmem_free(hi->hi_hook.h_name, strlen(hi->hi_hook.h_name) + 1);
	}

	/* Free container */
	kmem_free(hi, sizeof (*hi));
}
