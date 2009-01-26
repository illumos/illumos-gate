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
 * Remove objects.  Objects need removal from a process as part of:
 *
 *  o	a dlclose() request
 *
 *  o	tearing down a dlopen(), lazy-load, or filter hierarchy that failed to
 *	completely load
 *
 * Any other failure condition will result in process exit (in which case all
 * we have to do is execute the fini's - tear down is unnecessary).
 *
 * Any removal of objects is therefore associated with a dlopen() handle.  There
 * is a small window between creation of the first dlopen() object and creating
 * its handle (in which case remove_so() can get rid of the new link-map if
 * necessary), but other than this all object removal is driven by inspecting
 * the components of a handle.
 *
 * Things to note.  The creation of a link-map, and its addition to the link-map
 * list occurs in {elf|aout}_new_lm(), if this returns success the link-map is
 * valid and added, otherwise any steps (allocations) in the process of creating
 * the link-map would have been undone.  If a failure occurs between creating
 * the link-map and adding it to a handle, remove_so() is called to remove the
 * link-map.  If a failures occurs after a handle have been created,
 * remove_hdl() is called to remove the handle and the link-map.
 */

#include	<string.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<dlfcn.h>
#include	<sys/debug.h>
#include	<sys/avl.h>
#include	<libc_int.h>
#include	<debug.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

/*
 * Atexit callback provided by libc.  As part of dlclose() determine the address
 * ranges of all objects that are to be deleted.  Pass this information to
 * libc's pre-atexit routine.  Libc will purge any registered atexit() calls
 * related to those objects about to be deleted.
 */
static int
purge_exit_handlers(Lm_list *lml, Rt_map **tobj)
{
	uint_t			num;
	Rt_map			**_tobj;
	Lc_addr_range_t		*addr, *_addr;
	int			error;
	int			(*fptr)(Lc_addr_range_t *, uint_t);

	/*
	 * Has a callback been established?
	 */
	if ((fptr = lml->lm_lcs[CI_ATEXIT].lc_un.lc_func) == NULL)
		return (0);

	/*
	 * Determine the total number of mapped segments that will be unloaded.
	 */
	for (num = 0, _tobj = tobj; *_tobj != NULL; _tobj++) {
		Rt_map	*lmp = *_tobj;

		num += MMAPCNT(lmp);
	}

	/*
	 * Account for a null entry at the end of the address range array.
	 */
	if (num++ == 0)
		return (0);

	/*
	 * Allocate an array for the address range.
	 */
	if ((addr = malloc(num * sizeof (Lc_addr_range_t))) == NULL)
		return (1);

	/*
	 * Fill the address range with each loadable segments size and address.
	 */
	for (_tobj = tobj, _addr = addr; *_tobj != NULL; _tobj++) {
		Rt_map			*lmp = *_tobj;
		mmapobj_result_t	*mpp = MMAPS(lmp);
		uint_t			ndx;

		for (ndx = 0; ndx < MMAPCNT(lmp); ndx++, mpp++) {
			_addr->lb = (void *)(uintptr_t)(mpp->mr_addr +
			    mpp->mr_offset);
			_addr->ub = (void *)(uintptr_t)(mpp->mr_addr +
			    mpp->mr_msize);
			_addr++;
		}
	}
	_addr->lb = _addr->ub = 0;

	leave(LIST(*tobj), 0);
	error = (*fptr)(addr, (num - 1));
	(void) enter(0);

	/*
	 * If we fail to converse with libc, generate an error message to
	 * satisfy any dlerror() usage.
	 */
	if (error)
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ATEXIT), error);

	free(addr);
	return (error);
}

/*
 * Break down an Alist containing pathname descriptors.  In most instances, the
 * Alist is cleaned of all entries, but retained for later use.
 */
void
remove_plist(Alist **alpp, int complete)
{
	Alist	*alp = *alpp;

	if (alp) {
		if (complete) {
			free((void *)alp);
			*alpp = NULL;
		} else {
			alp->al_nitems = 0;
			alp->al_next = ALIST_OFF_DATA;
		}
	}
}

/*
 * Remove a link-map list descriptor.  This is called to finalize the removal
 * of an entire link-map list, after all link-maps have been removed, or none
 * got added.  As load_one() can process a list of potential candidate objects,
 * the link-map descriptor must be maintained as each object is processed.  Only
 * after all objects have been processed can a failure condition finally tear
 * down the link-map list descriptor.
 */
void
remove_lml(Lm_list *lml)
{
	if (lml && (lml->lm_head == NULL)) {
		/*
		 * As a whole link-map list is being removed, the debuggers
		 * would have been alerted of this deletion (or an addition
		 * in the case we're here to clean up from a failure).  Set
		 * the main link-map list so that a consistent registration
		 * can be signaled to the debuggers when we leave ld.so.1.
		 */
		lml_main.lm_flags |= LML_FLG_DBNOTIF;

		if (lml->lm_lmidstr)
			free(lml->lm_lmidstr);
		if (lml->lm_alp)
			free(lml->lm_alp);
		if (lml->lm_lists)
			free(lml->lm_lists);
		if (lml->lm_actaudit)
			free(lml->lm_actaudit);

		/*
		 * Cleanup any pending RTLDINFO in the case where it was
		 * allocated but not called (see _relocate_lmc()).
		 */
		if (lml->lm_rti)
			free(lml->lm_rti);
		if (lml->lm_fpavl) {
			/*
			 * As we are freeing the link-map list, all nodes must
			 * have previously been removed.
			 */
			ASSERT(avl_numnodes(lml->lm_fpavl) == 0);
			free(lml->lm_fpavl);
		}
		list_delete(&dynlm_list, lml);
		free(lml);
	}
}

/*
 * Remove a link-map.  This removes a link-map from its associated list and
 * free's up the link-map itself.  Note, all components that are freed are local
 * to the link-map, no inter-link-map lists are operated on as these are all
 * broken down by dlclose() while all objects are still mapped.
 *
 * This routine is called from dlclose() to zap individual link-maps after their
 * interdependencies (DEPENDS(), CALLER(), handles, etc.) have been removed.
 * This routine is also called from the bowels of load_one() in the case of a
 * link-map creation failure.
 */
void
remove_so(Lm_list *lml, Rt_map *lmp)
{
	Dyninfo *dip;

	if (lmp == NULL)
		return;

	/*
	 * Unlink the link map from the link-map list.
	 */
	if (lml && lmp)
		lm_delete(lml, lmp);

	/*
	 * If this object contributed any local external vectors for the current
	 * link-map list, remove the vectors.  If this object contributed any
	 * global external vectors we should find some new candidates, or leave
	 * this object lying around.
	 */
	if (lml) {
		int	tag;

		for (tag = 0; tag < CI_MAX; tag++) {
			if (lml->lm_lcs[tag].lc_lmp == lmp) {
				lml->lm_lcs[tag].lc_lmp = NULL;
				lml->lm_lcs[tag].lc_un.lc_val = 0;
			}
			if (glcs[tag].lc_lmp == lmp) {
				ASSERT(glcs[tag].lc_lmp != NULL);
				glcs[tag].lc_lmp = NULL;
				glcs[tag].lc_un.lc_val = 0;
			}
		}
	}

	DBG_CALL(Dbg_file_delete(lmp));

	/*
	 * If this is a temporary link-map, put in place to facilitate the
	 * link-edit or a relocatable object, then the link-map contains no
	 * information that needs to be cleaned up.
	 */
	if (FLAGS(lmp) & FLG_RT_OBJECT)
		return;

	/*
	 * Remove any FullpathNode AVL names if they still exist.
	 */
	if (FPNODE(lmp))
		fpavl_remove(lmp);

	/*
	 * Remove any alias names.
	 */
	if (ALIAS(lmp))
		free(ALIAS(lmp));

	/*
	 * Remove any of this objects filtee infrastructure.  The filtees them-
	 * selves have already been removed.
	 */
	if (((dip = DYNINFO(lmp)) != NULL) && (FLAGS1(lmp) & MSK_RT_FILTER)) {
		uint_t	cnt, max = DYNINFOCNT(lmp);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			if ((dip->di_info == NULL) ||
			    ((dip->di_flags & MSK_DI_FILTER) == 0))
				continue;

			remove_plist((Alist **)&(dip->di_info), 1);
		}
	}

	/*
	 * Deallocate any remaining cruft and free the link-map.
	 */
	if (RLIST(lmp))
		remove_plist(&RLIST(lmp), 1);

	if (AUDITORS(lmp))
		audit_desc_cleanup(lmp);
	if (AUDINFO(lmp))
		audit_info_cleanup(lmp);

	/*
	 * Note that COPY_R() and COPY_S() reference the same memory
	 * location, and that we want to release the memory referenced
	 * without regard to which list it logically belongs to. We can
	 * use either pointer to do this.
	 */
	if (COPY_R(lmp))
		free(COPY_R(lmp));

	/*
	 * During a dlclose() any groups this object was a part of will have
	 * been torn down.  However, we can get here to remove an object that
	 * has failed to load, perhaps because its addition to a handle failed.
	 * Therefore if this object indicates that its part of a group tear
	 * these associations down.
	 */
	if (GROUPS(lmp) != NULL) {
		Aliste	idx1;
		Grp_hdl	*ghp;

		for (APLIST_TRAVERSE(GROUPS(lmp), idx1, ghp)) {
			Grp_desc	*gdp;
			Aliste		idx2;

			for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
				if (gdp->gd_depend != lmp)
					continue;

				alist_delete(ghp->gh_depends, &idx2);
				break;
			}
		}
		free(GROUPS(lmp));
	}
	if (HANDLES(lmp))
		free(HANDLES(lmp));

	/*
	 * Clean up reglist if needed
	 */
	if (reglist) {
		Reglist	*cur, *prv, *del;

		cur = prv = reglist;
		while (cur) {
			if (cur->rl_lmp == lmp) {
				del = cur;
				if (cur == reglist) {
					reglist = cur->rl_next;
					cur = prv = reglist;
				} else {
					prv->rl_next = cur->rl_next;
					cur = cur->rl_next;
				}
				free(del);
			} else {
				prv = cur;
				cur = cur->rl_next;
			}
		}
	}

	/*
	 * If this link map represents a relocatable object concatenation, then
	 * the image was simply generated in allocated memory.  Free the memory.
	 * Note: memory maps were fabricated for the relocatable object, and
	 * the mapping infrastructure must be free'd, but there are no address
	 * mappings that must be unmapped.
	 *
	 * Otherwise, unmap the object.
	 */
	if (FLAGS(lmp) & FLG_RT_IMGALLOC)
		free((void *)ADDR(lmp));

	if (MMAPS(lmp)) {
		if ((FLAGS(lmp) & FLG_RT_IMGALLOC) == 0)
			unmap_obj(MMAPS(lmp), MMAPCNT(lmp));
		free(MMAPS(lmp));
	}

	free(lmp);
}

/*
 * Traverse an objects dependency list removing callers and dependencies.
 * There's a chicken and egg problem with tearing down link-maps.  Any
 * relationship between link-maps is maintained on a DEPENDS list, and an
 * associated CALLERS list.  These lists can't be broken down at the time a
 * single link-map is removed, as any related link-map may have already been
 * removed.  Thus, lists between link-maps must be broken down before the
 * individual link-maps themselves.
 */
static void
remove_lists(Rt_map *lmp, int lazy)
{
	Aliste		idx1;
	Bnd_desc	*bdp;

	/*
	 * First, traverse this objects dependencies.
	 */
	for (APLIST_TRAVERSE(DEPENDS(lmp), idx1, bdp)) {
		Rt_map		*dlmp = bdp->b_depend;

		/*
		 * Remove this object from the dependencies callers.
		 */
		(void) aplist_delete_value(CALLERS(dlmp), bdp);
		free(bdp);
	}
	if (DEPENDS(lmp)) {
		free(DEPENDS(lmp));
		DEPENDS(lmp) = NULL;
	}

	/*
	 * Second, traverse this objects callers.
	 */
	for (APLIST_TRAVERSE(CALLERS(lmp), idx1,  bdp)) {
		Rt_map		*clmp = bdp->b_caller;
		Dyninfo		*dip;

		/*
		 * If we're removing an object that was triggered by a lazyload,
		 * remove the callers DYNINFO() entry and bump the lazy counts.
		 * This reinitialization of the lazy information allows a lazy
		 * object to be reloaded again later.  Although we may be
		 * breaking down a group of lazyloaded objects because one has
		 * failed to relocate, it's possible that one or more of the
		 * individual objects can be reloaded without a problem.
		 */
		if (lazy && ((dip = DYNINFO(clmp)) != NULL)) {
			uint_t	cnt, max = DYNINFOCNT(clmp);

			for (cnt = 0; cnt < max; cnt++, dip++) {
				if ((dip->di_flags & FLG_DI_LAZY) == 0)
					continue;

				if (dip->di_info == (void *)lmp) {
					dip->di_info = NULL;

					if (LAZY(clmp)++ == 0)
						LIST(clmp)->lm_lazy++;
				}
			}
		}

		(void) aplist_delete_value(DEPENDS(clmp), bdp);
		free(bdp);
	}
	if (CALLERS(lmp)) {
		free(CALLERS(lmp));
		CALLERS(lmp) = NULL;
	}
}

/*
 * Delete any temporary link-map control list.
 */
void
remove_cntl(Lm_list *lml, Aliste lmco)
{
	if (lmco && (lmco != ALIST_OFF_DATA)) {
		Aliste	_lmco = lmco;
#if	DEBUG
		Lm_cntl	*lmc;

		lmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, lmco);

		/*
		 * This element should be empty.
		 */
		ASSERT(lmc->lc_head == NULL);
#endif
		alist_delete_by_offset(lml->lm_lists, &_lmco);
	}
}

/*
 * If a lazy loaded object, or filtee fails to load, possibly because it, or
 * one of its dependencies can't be relocated, then tear down any objects
 * that are apart of this link-map control list.
 */
static void
remove_incomplete(Lm_list *lml, Aliste lmco)
{
	Rt_map	*lmp;
	Lm_cntl	*lmc;

	/* LINTED */
	lmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, lmco);

	/*
	 * First, remove any lists that may point between objects.
	 */
	for (lmp = lmc->lc_head; lmp; lmp = NEXT_RT_MAP(lmp))
		remove_lists(lmp, 1);

	/*
	 * Finally, remove each object.  remove_so() calls lm_delete(), thus
	 * effectively the link-map control head gets updated to point to the
	 * next link-map.
	 */
	while ((lmp = lmc->lc_head) != NULL)
		remove_so(lml, lmp);

	lmc->lc_head = lmc->lc_tail = NULL;
}

/*
 * Determine whether an object is deletable.
 */
static int
is_deletable(APlist **lmalp, APlist **ghalp, Rt_map *lmp)
{
	Aliste		idx;
	Bnd_desc	*bdp;
	Grp_hdl		*ghp;

	/*
	 * If the object hasn't yet been relocated take this as a sign that
	 * it's loading failed, thus we're here to cleanup.  If the object is
	 * relocated it will only be retained if it was marked non-deletable,
	 * and exists on the main link-map control list.
	 */
	if ((FLAGS(lmp) & FLG_RT_RELOCED) &&
	    (MODE(lmp) & RTLD_NODELETE) && (CNTL(lmp) == ALIST_OFF_DATA))
		return (0);

	/*
	 * If this object is the head of a handle that has not been captured as
	 * a candidate for deletion, then this object is in use from a dlopen()
	 * outside of the scope of this dlclose() family.  Dlopen'ed objects,
	 * and filtees, have group descriptors for their callers.  Typically
	 * this parent will have callers that are not apart of this dlclose()
	 * family, and thus would be caught by the CALLERS test below.  However,
	 * if the caller had itself been dlopen'ed, it may not have any explicit
	 * callers registered for itself.  Thus, but looking for objects with
	 * handles we can ferret out these outsiders.
	 */
	for (APLIST_TRAVERSE(HANDLES(lmp), idx, ghp)) {
		if (aplist_test(ghalp, ghp, 0) != ALE_EXISTS)
			return (0);
	}

	/*
	 * If this object is called by any object outside of the family of
	 * objects selected for deletion, it can't be deleted.
	 */
	for (APLIST_TRAVERSE(CALLERS(lmp), idx, bdp)) {
		if (aplist_test(lmalp, bdp->b_caller, 0) !=
		    ALE_EXISTS)
			return (0);
	}

	/*
	 * This object is a candidate for deletion.
	 */
	return (1);
}

/*
 * Collect the groups (handles) and associated objects that are candidates for
 * deletion.  The criteria for deleting an object is whether it is only refer-
 * enced from the objects within the groups that are candidates for deletion.
 */
static int
gdp_collect(APlist **ghalpp, APlist **lmalpp, Grp_hdl *ghp1)
{
	Aliste		idx1;
	Grp_desc	*gdp;
	int		action;

	/*
	 * Add this group to our group collection.  If it isn't added either an
	 * allocation has failed, or it already exists.
	 */
	if ((action = aplist_test(ghalpp, ghp1, AL_CNT_GRPCLCT)) !=
	    ALE_CREATE)
		return (action);

	/*
	 * Traverse the dependencies of the group and collect the associated
	 * objects.
	 */
	for (ALIST_TRAVERSE(ghp1->gh_depends, idx1, gdp)) {
		Rt_map	*lmp = gdp->gd_depend;

		/*
		 * We only want to process dependencies for deletion.  Although
		 * we want to purge group descriptors for parents, we don't want
		 * to analyze the parent itself for additional filters or
		 * deletion.
		 */
		if ((gdp->gd_flags & GPD_PARENT) ||
		    ((gdp->gd_flags & GPD_ADDEPS) == 0))
			continue;

		if ((action = aplist_test(lmalpp, lmp, AL_CNT_GRPCLCT)) ==
		    ALE_ALLOCFAIL)
			return (0);
		if (action == ALE_EXISTS)
			continue;

		/*
		 * If this object is a candidate for deletion, determine if the
		 * object provides any filtees.  If so, the filter groups are
		 * added to the group collection.
		 *
		 * An object is a candidate for deletion if:
		 *
		 *  .	the object hasn't yet been relocated, in which case
		 *	we're here to clean up a failed load, or
		 *  .	the object doesn't reside on the base link-map control
		 *	list, in which case a group of objects, typically
		 *	lazily loaded, or filtees, need cleaning up, or
		 *  .   the object isn't tagged as non-deletable.
		 */
		if ((((FLAGS(lmp) & FLG_RT_RELOCED) == 0) ||
		    (CNTL(lmp) != ALIST_OFF_DATA) ||
		    ((MODE(lmp) & RTLD_NODELETE) == 0)) &&
		    (FLAGS1(lmp) & MSK_RT_FILTER)) {
			Dyninfo	*dip = DYNINFO(lmp);
			uint_t	cnt, max = DYNINFOCNT(lmp);

			for (cnt = 0; cnt < max; cnt++, dip++) {
				Alist	*falp;
				Aliste	idx2;
				Pdesc	*pdp;

				if (((falp = (Alist *)dip->di_info) == NULL) ||
				    ((dip->di_flags & MSK_DI_FILTER) == 0))
					continue;

				for (ALIST_TRAVERSE(falp, idx2, pdp)) {
					Grp_hdl	*ghp2;

					if ((pdp->pd_plen == 0) || ((ghp2 =
					    (Grp_hdl *)pdp->pd_info) == NULL))
						continue;

					if (gdp_collect(ghalpp, lmalpp,
					    ghp2) == 0)
						return (0);
				}
			}
		}
	}
	return (1);
}

/*
 * Traverse the list of deletable candidates.  If an object can't be deleted
 * then neither can its dependencies or filtees.  Any object that is cleared
 * from being deleted drops the deletion count, plus, if there are no longer
 * any deletions pending we can discontinue any further processing.
 */
static int
remove_rescan(APlist *lmalp, APlist *ghalp, int *delcnt)
{
	Aliste		idx1;
	Rt_map		*lmp;
	int		rescan = 0;

	for (APLIST_TRAVERSE(lmalp, idx1, lmp)) {
		Aliste		idx2;
		Bnd_desc	*bdp;
		Dyninfo		*dip;
		uint_t		cnt, max;

		if (FLAGS(lmp) & FLG_RT_DELETE)
			continue;

		/*
		 * As this object can't be deleted, make sure its dependencies
		 * aren't deleted either.
		 */
		for (APLIST_TRAVERSE(DEPENDS(lmp), idx2, bdp)) {
			Rt_map	*dlmp = bdp->b_depend;

			if (FLAGS(dlmp) & FLG_RT_DELETE) {
				FLAGS(dlmp) &= ~FLG_RT_DELETE;
				if (--(*delcnt) == 0)
					return (0);
				rescan = 1;
			}
		}

		/*
		 * If this object is a filtee and one of its filters is outside
		 * of this dlclose family, then it can't be deleted either.
		 */
		if ((FLAGS1(lmp) & MSK_RT_FILTER) == 0)
			continue;

		dip = DYNINFO(lmp);
		max = DYNINFOCNT(lmp);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			Alist	*falp;
			Pdesc	*pdp;

			if (((falp = (Alist *)dip->di_info) == NULL) ||
			    ((dip->di_flags & MSK_DI_FILTER) == 0))
				continue;

			for (ALIST_TRAVERSE(falp, idx2, pdp)) {
				Aliste		idx3;
				Grp_hdl		*ghp;
				Grp_desc	*gdp;

				if ((pdp->pd_plen == 0) ||
				    ((ghp = (Grp_hdl *)pdp->pd_info) == NULL))
					continue;

				if (aplist_test(&ghalp, ghp, 0) ==
				    ALE_EXISTS)
					continue;

				for (ALIST_TRAVERSE(ghp->gh_depends, idx3,
				    gdp)) {
					Rt_map	*dlmp = gdp->gd_depend;

					if (FLAGS(dlmp) & FLG_RT_DELETE) {
						FLAGS(dlmp) &= ~FLG_RT_DELETE;
						if (--(*delcnt) == 0)
							return (0);
						rescan = 1;
					}
				}

				/*
				 * Remove this group handle from our dynamic
				 * deletion list.
				 */
				(void) aplist_delete_value(ghalp, ghp);
			}
		}
	}
	return (rescan);
}

/*
 * Cleanup any collection alists we've created.
 */
static void
remove_collect(APlist *ghalp, APlist *lmalp)
{
	if (ghalp)
		free(ghalp);
	if (lmalp)
		free(lmalp);
}

/*
 * Remove a handle, leaving the associated objects intact.  Besides the classic
 * dlopen() usage, handles are used as a means of associating a group of objects
 * and promoting modes.  Once object promotion is completed, the handle should
 * be discarded while leaving the associated objects intact.  Leaving the handle
 * would prevent the object from being deleted (as it looks like it's in use
 * by another user).
 */
void
free_hdl(Grp_hdl *ghp, Rt_map *clmp, uint_t cdflags)
{
	Grp_desc	*gdp;
	Aliste		idx;

	if (--(ghp->gh_refcnt) == 0) {
		uintptr_t	ndx;

		for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
			Rt_map	*lmp = gdp->gd_depend;

			if (ghp->gh_ownlmp == lmp)
				(void) aplist_delete_value(HANDLES(lmp), ghp);
			(void) aplist_delete_value(GROUPS(lmp), ghp);
		}
		(void) free(ghp->gh_depends);

		/* LINTED */
		ndx = (uintptr_t)ghp % HDLIST_SZ;
		(void) aplist_delete_value(hdl_alp[ndx], ghp);

		(void) free(ghp);

	} else if (clmp) {
		/*
		 * It's possible that an RTLD_NOW promotion (via GPD_PROMOTE)
		 * has associated a caller with a handle that is already in use.
		 * In this case, find the caller and either remove the caller
		 * from the handle, or if the caller is used for any other
		 * reason, clear the promotion flag.
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
			Rt_map	*lmp = gdp->gd_depend;

			if (lmp != clmp)
				continue;

			if (gdp->gd_flags == cdflags) {
				alist_delete(ghp->gh_depends, &idx);
				(void) aplist_delete_value(GROUPS(lmp), ghp);
			} else {
				gdp->gd_flags &= ~cdflags;
			}
			return;
		}
	}
}

/*
 * If a load operation, using a new link-map control list, has failed, then
 * forcibly remove the failed objects.  This failure can occur as a result
 * of a lazy load, a dlopen(), or a filtee load, once the application is
 * running.  If the link-map control list has not yet started relocation, then
 * cleanup is simply a process of removing all the objects from the control
 * list.  If relocation has begun, then other loads may have been triggered to
 * satisfy the relocations, and thus we need to break down the control list
 * using handles.
 *
 * The objects associated with this load must be part of a unique handle.  In
 * the case of a dlopen() or filtee request, a handle will have been created.
 * For a lazyload request, a handle must be generated so that the remove
 * process can use the handle.
 *
 * During the course of processing these objects, other objects (handles) may
 * have been loaded to satisfy relocation requirements.  After these families
 * have successfully loaded, they will have been propagated to the same link-map
 * control list.  The failed objects need to be removed from this list, while
 * any successfully loaded families can be left alone, and propagated to the
 * previous link-map control list.  By associating each load request with a
 * handle, we can isolate the failed objects while not interfering with any
 * successfully loaded families.
 */
void
remove_lmc(Lm_list *lml, Rt_map *clmp, Lm_cntl *lmc, Aliste lmco,
    const char *name)
{
	Grp_hdl		*ghp;
	Grp_desc	*gdp;
	Aliste		idx;
	Rt_map		*lmp;

	DBG_CALL(Dbg_file_cleanup(lml, name, lmco));

	/*
	 * Obtain a handle for the first object on the link-map control list.
	 * If none exists (which would occur from a lazy load request), and
	 * the link-map control list is being relocated, create a handle.
	 */
	lmp = lmc->lc_head;
	if (HANDLES(lmp)) {
		ghp = (Grp_hdl *)HANDLES(lmp)->apl_data[0];

	} else if (lmc->lc_flags & LMC_FLG_RELOCATING) {
		/*
		 * Establish a handle, and should anything fail, fall through
		 * to remove the link-map control list.
		 */
		if (((ghp = hdl_create(lml, lmc->lc_head, 0, 0,
		    GPD_ADDEPS, 0)) == NULL) ||
		    (hdl_initialize(ghp, lmc->lc_head, 0, 0) == 0))
			lmc->lc_flags &= ~LMC_FLG_RELOCATING;
	} else {
		ghp = NULL;
	}

	/*
	 * If relocation hasn't begun, simply remove all the objects from this
	 * list, and any handle that may have been created.
	 */
	if ((lmc->lc_flags & LMC_FLG_RELOCATING) == 0) {
		remove_incomplete(lml, lmco);

		if (ghp) {
			ghp->gh_refcnt = 1;
			free_hdl(ghp, 0, 0);
		}
		return;
	}

	ASSERT(ghp != NULL);

	/*
	 * As the objects of this handle are being forcibly removed, first
	 * remove any associations to objects on parent link-map control
	 * lists.  This breaks the bond between a caller and a hierarchy of
	 * dependencies represented by the handle, thus the caller doesn't lock
	 * the hierarchy and prevent their deletion from the generic handle
	 * processing or remove_hdl().
	 *
	 * This scenario can be produced when the relocation of a object
	 * results in vectoring through a filter that is already loaded.  The
	 * filtee may be on the link-map list that is presently being processed,
	 * however an association between the filter and filtee would have been
	 * established during filtee processing.  It is this association that
	 * must be broken to allow the objects on this link-map list to be
	 * removed.
	 */
	for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
		Rt_map	*lmp = gdp->gd_depend;

		/*
		 * If this object has not been relocated, break down any
		 * dependency relationships the object might have established.
		 */
		if ((FLAGS(lmp) & FLG_RT_RELOCED) == 0)
			remove_lists(lmp, 1);

		if (CNTL(lmp) == lmco)
			continue;

		if (gdp->gd_flags & GPD_FILTER) {
			Dyninfo	*dip = DYNINFO(lmp);
			uint_t	cnt, max = DYNINFOCNT(lmp);

			for (cnt = 0; cnt < max; cnt++, dip++) {
				Alist	*falp;
				Aliste	idx2;
				Pdesc	*pdp;

				if (((falp = (Alist *)dip->di_info) == NULL) ||
				    ((dip->di_flags & MSK_DI_FILTER) == 0))
					continue;

				for (ALIST_TRAVERSE(falp, idx2, pdp)) {
					if ((Grp_hdl *)pdp->pd_info == ghp) {
						pdp->pd_info = NULL;
						break;
					}
				}
			}
		}
		(void) aplist_delete_value(GROUPS(lmp), ghp);
		alist_delete(ghp->gh_depends, &idx);
	}

	/*
	 * Having removed any callers, set the group handle reference count to
	 * one, and let the generic handle remover delete the associated
	 * objects.
	 */
	ghp->gh_refcnt = 1;
	(void) remove_hdl(ghp, clmp, NULL);

	/*
	 * If this link-map control list still contains objects, determine the
	 * previous control list and move the objects.
	 */
	if (lmc->lc_head) {
		Lm_cntl *plmc;
		Aliste  plmco;

		plmco = lmco - lml->lm_lists->al_size;
		/* LINTED */
		plmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, plmco);

		lm_move(lml, lmco, plmco, lmc, plmc);
	}
}

/*
 * Remove the objects associated with a handle.  There are two goals here, to
 * delete the objects associated with the handle, and to remove the handle
 * itself.  Things get a little more complex if the objects selected for
 * deletion are filters, in this case we also need to collect their filtees,
 * and process the combined groups as a whole.  But, care still must be exer-
 * cised to make sure any filtees found aren't being used by filters outside of
 * the groups we've collect.  The series of events is basically:
 *
 *  o	Determine the groups (handles) that might be deletable.
 *
 *  o	Determine the objects of these handles that can be deleted.
 *
 *  o	Fire the fini's of those objects selected for deletion.
 *
 *  o	Remove all inter-dependency linked lists while the objects link-maps
 *	are still available.
 *
 *  o	Remove all deletable objects link-maps and unmap the objects themselves.
 *
 *  o	Remove the handle descriptors for each deleted object, and hopefully
 *	the whole handle.
 *
 * An handle that can't be deleted is added to an orphans list.  This list is
 * revisited any time another dlclose() request results in handle descriptors
 * being deleted.  These deleted descriptors can be sufficient to allow the
 * final deletion of the orphaned handles.
 */
int
remove_hdl(Grp_hdl *ghp, Rt_map *clmp, int *removed)
{
	Rt_map		*lmp;
	int		rescan = 0;
	int		delcnt = 0, rmcnt = 0, error = 0, orphans;
	APlist		*lmalp = NULL, *ghalp = NULL;
	Aliste		idx1, idx2;
	Grp_hdl		*ghp2;
	Grp_desc	*gdp;
	Lm_list		*lml = NULL;

	/*
	 * Generate the family of groups and objects that are candidates for
	 * deletion.  This consists of the objects that are explicitly defined
	 * as dependencies of this handle, plus any filtee handles and their
	 * associated objects.
	 */
	if (gdp_collect(&ghalp, &lmalp, ghp) == 0) {
		remove_collect(ghalp, lmalp);
		return (0);
	}

	DBG_CALL(Dbg_file_hdl_title(DBG_HDL_DELETE));

	/*
	 * Traverse the groups we've collected to determine if any filtees are
	 * included.  If so, and the filtee handle is in use by a filter outside
	 * of the family of objects collected for this deletion, it can not be
	 * removed.
	 */
	for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
		Grp_hdl	*ghp = ghp2;

		DBG_CALL(Dbg_file_hdl_collect(ghp, 0));

		if ((ghp->gh_flags & GPH_FILTEE) == 0)
			continue;

		/*
		 * Special case for ld.so.1.  There can be multiple instances of
		 * libdl.so.1 using this handle, so although we want the handles
		 * reference count to be decremented, we don't want the handle
		 * removed.
		 */
		if (ghp->gh_flags & GPH_LDSO) {
			DBG_CALL(Dbg_file_hdl_collect(ghp,
			    NAME(lml_rtld.lm_head)));
			aplist_delete(ghalp, &idx1);
			continue;
		}

		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			Grp_hdl	*ghp3;
			Aliste	idx3;

			/*
			 * Determine whether this dependency is the filtee's
			 * parent filter, and that it isn't also an explicit
			 * dependency (in which case it would have added its own
			 * dependencies to the handle).
			 */
			if ((gdp->gd_flags &
			    (GPD_FILTER | GPD_ADDEPS)) != GPD_FILTER)
				continue;

			if (aplist_test(&lmalp, gdp->gd_depend, 0) ==
			    ALE_EXISTS)
				continue;

			/*
			 * Remove this group handle from our dynamic deletion
			 * list.  In addition, recompute the list of objects
			 * that are candidates for deletion to continue this
			 * group verification.
			 */
			DBG_CALL(Dbg_file_hdl_collect(ghp,
			    NAME(gdp->gd_depend)));
			aplist_delete(ghalp, &idx1);

			free(lmalp);
			lmalp = NULL;
			for (APLIST_TRAVERSE(ghalp, idx3, ghp3)) {
				Aliste		idx4;
				Grp_desc	*gdp4;

				for (ALIST_TRAVERSE(ghp3->gh_depends,
				    idx4, gdp4))  {
					if ((gdp4->gd_flags & GPD_ADDEPS) == 0)
						continue;
					if (aplist_test(&lmalp, gdp4->gd_depend,
					    AL_CNT_GRPCLCT) == ALE_ALLOCFAIL) {
						remove_collect(ghalp, lmalp);
						return (0);
					}
				}
			}
			break;
		}
	}

	/*
	 * Now that we've collected all the handles dependencies, traverse the
	 * collection determining whether they are a candidate for deletion.
	 */
	for (APLIST_TRAVERSE(lmalp, idx1, lmp)) {
		/*
		 * Establish which link-map list we're dealing with for later
		 * .fini processing.
		 */
		if (lml == NULL)
			lml = LIST(lmp);

		/*
		 * If an object isn't a candidate for deletion we'll have to
		 * rescan the handle insuring that this objects dependencies
		 * aren't deleted either.
		 */
		if (is_deletable(&lmalp, &ghalp, lmp)) {
			FLAGS(lmp) |= FLG_RT_DELETE;
			delcnt++;
		} else
			rescan = 1;
	}

	/*
	 * Rescan the handle if any objects where found non-deletable.
	 */
	while (rescan)
		rescan = remove_rescan(lmalp, ghalp, &delcnt);

	/*
	 * Now that we have determined the number of groups that are candidates
	 * for removal, mark each group descriptor as a candidate for removal
	 * from the group.
	 */
	for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
		for (ALIST_TRAVERSE(ghp2->gh_depends, idx2, gdp))
			gdp->gd_flags |= GPD_REMOVE;
	}

	/*
	 * Now that we know which objects on this handle can't be deleted
	 * determine whether they still need to remain identified as belonging
	 * to this group to be able to continue binding to one another.
	 */
	for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
		Grp_hdl	*ghp = ghp2;

		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			Aliste		idx3;
			Bnd_desc	*bdp;

			lmp = gdp->gd_depend;

			if (FLAGS(lmp) & FLG_RT_DELETE)
				continue;

			for (APLIST_TRAVERSE(DEPENDS(lmp), idx3, bdp)) {
				Aliste 		idx4;
				Grp_desc	*gdp4;
				Rt_map		*dlmp = bdp->b_depend;

				/*
				 * If this dependency (dlmp) can be referenced
				 * by the caller (clmp) without being part of
				 * this group (ghp) then belonging to this group
				 * is no longer necessary.  This can occur when
				 * objects are part of multiple handles, or if a
				 * previously deleted handle was moved to the
				 * orphan list and has been reopened.  Note,
				 * first make sure the caller can reference the
				 * dependency with this group, if it can't we
				 * must be bound to a filtee, so there's no need
				 * to remain a part of this group either.
				 */
				if ((callable(lmp, dlmp, 0, 0) == 0) ||
				    callable(lmp, dlmp, ghp, 0))
					continue;

				if (gdp->gd_flags & GPD_REMOVE)
					gdp->gd_flags &= ~GPD_REMOVE;

				for (ALIST_TRAVERSE(ghp->gh_depends,
				    idx4, gdp4)) {
					if (gdp4->gd_depend != dlmp)
						continue;

					if (gdp4->gd_flags & GPD_REMOVE)
						gdp4->gd_flags &= ~GPD_REMOVE;
				}
			}
		}
	}

	/*
	 * If the owner of a handle can't be deleted and it's handle descriptor
	 * must remain also, don't delete the handle at all.  Leave it for
	 * possible later use.  Although it's left intact, it will still be
	 * moved to the orphans list, as we might be able to revisit it on later
	 * dlclose() operations and finally remove the underlying objects.  Note
	 * that the handle still remains attached to the owner via the HANDLES
	 * list, so that it can be re-associated to the owner if a dlopen()
	 * of this object reoccurs.
	 */
	for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
		Grp_hdl	*ghp = ghp2;

		/*
		 * If this handle is already an orphan, or if it's owner is
		 * deletable there's no need to inspect its dependencies.
		 */
		if ((ghp->gh_ownlmp == NULL) ||
		    (FLAGS(ghp->gh_ownlmp) & FLG_RT_DELETE))
			continue;

		/*
		 * Make sure all handle dependencies aren't removed or the
		 * dependencies themselves aren't deleted.
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			lmp = gdp->gd_depend;

			/*
			 * The first dependency of a non-orphaned handle is the
			 * owner.  If the handle descriptor for this isn't
			 * required there's no need to look at any other of the
			 * handles dependencies.
			 */
			if ((lmp == ghp->gh_ownlmp) &&
			    (gdp->gd_flags & GPD_REMOVE))
				break;

			if (gdp->gd_flags & GPD_REMOVE)
				gdp->gd_flags &= ~GPD_REMOVE;
			if (FLAGS(lmp) & FLG_RT_DELETE) {
				FLAGS(lmp) &= ~FLG_RT_DELETE;
				delcnt--;
			}
		}
	}

	/*
	 * Final scan of objects to see if any objects are to to be deleted.
	 * Also - display diagnostic information on what operations are to be
	 * performed on the collected handles before firing .fini's (which
	 * produces additional diagnostics).
	 */
	for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
		Grp_hdl	*ghp = ghp2;

		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_DELETE));

		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			int	flag;

			lmp = gdp->gd_depend;

			/*
			 * Note, we must never delete a parent.  The parent
			 * may already be tagged for deletion from a previous
			 * dlclose(). That dlclose has triggered this dlclose(),
			 * but the parents deletion is the responsibility of the
			 * previous dlclose(), not this one.
			 */
			if ((FLAGS(lmp) & FLG_RT_DELETE) &&
			    ((gdp->gd_flags & GPD_PARENT) == 0)) {
				flag = DBG_DEP_DELETE;

				/*
				 * Remove any pathnames from the FullpathNode
				 * AVL tree.  As we're about to fire .fini's,
				 * it's possible this object will be required
				 * again, in which case we want to make sure a
				 * new version of the object gets loaded.
				 */
				if (FPNODE(lmp))
					fpavl_remove(lmp);
			} else if (gdp->gd_flags & GPD_REMOVE)
				flag = DBG_DEP_REMOVE;
			else
				flag = DBG_DEP_REMAIN;

			DBG_CALL(Dbg_file_hdl_action(ghp, lmp, flag, 0));
		}
	}

	/*
	 * If there are objects to be deleted process their .fini's.
	 */
	if (delcnt) {
		Rt_map	**tobj;

		/*
		 * If we're being audited tell the audit library that we're
		 * about to go deleting dependencies.
		 */
		if (clmp && ((LIST(clmp)->lm_tflags | AFLAGS(clmp)) &
		    LML_TFLG_AUD_ACTIVITY))
			audit_activity(clmp, LA_ACT_DELETE);

		/*
		 * Sort and fire all fini's of the objects selected for
		 * deletion.  Note that we have to start our search from the
		 * link-map head - there's no telling whether this object has
		 * dependencies on objects that were loaded before it and which
		 * can now be deleted.  If the tsort() fails because of an
		 * allocation error then that might just be a symptom of why
		 * we're here in the first place - forgo the fini's but
		 * continue to try cleaning up.
		 */
		lml->lm_flags |= LML_FLG_OBJDELETED;

		if (((tobj = tsort(lml->lm_head, delcnt,
		    (RT_SORT_DELETE | RT_SORT_FWD))) != NULL) &&
		    (tobj != (Rt_map **)S_ERROR)) {
			error = purge_exit_handlers(lml, tobj);
			call_fini(lml, tobj);
		}

		/*
		 * Audit the closure of the dlopen'ed object to any local
		 * auditors.  Any global auditors would have been caught by
		 * call_fini(), but as the link-maps CALLERS was removed
		 * already we do the local auditors explicitly.
		 */
		for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
			Grp_hdl	*ghp = ghp2;
			Rt_map	*dlmp = ghp->gh_ownlmp;

			if (clmp && dlmp &&
			    ((LIST(dlmp)->lm_flags & LML_FLG_NOAUDIT) == 0) &&
			    (AFLAGS(clmp) & LML_TFLG_AUD_OBJCLOSE))
				_audit_objclose(&(AUDITORS(clmp)->ad_list),
				    dlmp);
		}
	}

	/*
	 * Now that .fini processing (which may have involved new bindings)
	 * is complete, remove all inter-dependency lists from those objects
	 * selected for deletion.
	 */
	for (APLIST_TRAVERSE(lmalp, idx1, lmp)) {
		Dyninfo	*dip;
		uint_t	cnt, max;

		if (FLAGS(lmp) & FLG_RT_DELETE)
			remove_lists(lmp, 0);

		/*
		 * Determine whether we're dealing with a filter, and if so
		 * process any inter-dependencies with its filtee's.
		 */
		if ((FLAGS1(lmp) & MSK_RT_FILTER) == 0)
			continue;

		dip = DYNINFO(lmp);
		max = DYNINFOCNT(lmp);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			Alist	*falp;
			Aliste	idx2;
			Pdesc	*pdp;

			if (((falp = (Alist *)dip->di_info) == NULL) ||
			    ((dip->di_flags & MSK_DI_FILTER) == 0))
				continue;

			for (ALIST_TRAVERSE(falp, idx2, pdp)) {
				Grp_hdl	*ghp;

				if ((pdp->pd_plen == 0) ||
				    ((ghp = (Grp_hdl *)pdp->pd_info) == NULL))
					continue;

				/*
				 * Determine whether this filtee's handle is a
				 * part of the list of handles being deleted.
				 */
				if (aplist_test(&ghalp, ghp, 0) == ALE_EXISTS) {
					/*
					 * If this handle exists on the deletion
					 * list, then it has been removed.  If
					 * this filter isn't going to be
					 * deleted, sever its reference to the
					 * handle.
					 */
					pdp->pd_info = NULL;
				} else {
					/*
					 * If this handle isn't on the deletion
					 * list, then it must still exist.  If
					 * this filter is being deleted, make
					 * sure the filtees reference count
					 * gets decremented.
					 */
					if ((FLAGS(lmp) & FLG_RT_DELETE) &&
					    ((gdp->gd_flags &
					    GPD_PARENT) == 0)) {
						(void) dlclose_core(ghp,
						    lmp, lml);
					}
				}
			}
		}
	}

	/*
	 * If called from dlclose(), determine if there are already handles on
	 * the orphans list that we can reinvestigate.
	 */
	if ((removed == 0) && aplist_nitems(hdl_alp[HDLIST_ORP]))
		orphans = 1;
	else
		orphans = 0;

	/*
	 * Finally remove any handle infrastructure and remove any objects
	 * marked for deletion.
	 */
	for (APLIST_TRAVERSE(ghalp, idx1, ghp2)) {
		Grp_hdl	*ghp = ghp2;

		/*
		 * If we're not dealing with orphaned handles remove this handle
		 * from its present handle list.
		 */
		if (removed == 0) {
			uintptr_t ndx;

			/* LINTED */
			ndx = (uintptr_t)ghp % HDLIST_SZ;
			(void) aplist_delete_value(hdl_alp[ndx], ghp);
		}

		/*
		 * Traverse each handle dependency.  Retain the dependencies
		 * flags to insure we don't delete any parents (the flags
		 * information is deleted as part of the alist removal that
		 * occurs before we inspect the object for deletion).
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			uint_t	flags = gdp->gd_flags;

			if ((flags & GPD_REMOVE) == 0)
				continue;

			lmp = gdp->gd_depend;
			rmcnt++;

			/*
			 * If this object is the owner of the handle break that
			 * association in case the handle is retained.
			 */
			if (ghp->gh_ownlmp == lmp) {
				(void) aplist_delete_value(HANDLES(lmp), ghp);
				ghp->gh_ownlmp = NULL;
			}

			(void) aplist_delete_value(GROUPS(lmp), ghp);
			alist_delete(ghp->gh_depends, &idx2);

			/*
			 * Complete the link-map deletion if appropriate.
			 */
			if ((FLAGS(lmp) & FLG_RT_DELETE) &&
			    ((flags & GPD_PARENT) == 0)) {
				tls_modaddrem(lmp, TM_FLG_MODREM);
				remove_so(LIST(lmp), lmp);
			}
		}

		/*
		 * If we've deleted all the dependencies of the handle, finalize
		 * the cleanup by removing the handle itself.
		 *
		 * Otherwise we're left with a handle containing one or more
		 * objects that can not be deleted (they're in use by other
		 * handles, non-deletable, etc.), but require to remain a part
		 * of this group to allow them to continue binding to one
		 * another.
		 *
		 * If the handles reference count is zero, or represents a
		 * link-map list (dlopen(0)), then move that handle to the
		 * orphans list.  Should another dlclose() operation occur that
		 * results in the removal of handle descriptors, these orphan
		 * handles are re-examined to determine if their deletion can
		 * be completed.
		 */
		if (ghp->gh_depends->al_nitems == 0) {
			free(ghp->gh_depends);
			free(ghp);

		} else if ((ghp->gh_refcnt == 0) &&
		    ((ghp->gh_flags & GPH_ZERO) == 0)) {
			/*
			 * Move this handle to the orphans list.
			 */
			(void) aplist_append(&hdl_alp[HDLIST_ORP], ghp,
			    AL_CNT_HANDLES);

			if (DBG_ENABLED) {
				DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ORPHAN));
				for (ALIST_TRAVERSE(ghp->gh_depends, idx1, gdp))
					DBG_CALL(Dbg_file_hdl_action(ghp,
					    gdp->gd_depend, DBG_DEP_ORPHAN, 0));
			}
		}
	}

	/*
	 * If no handle descriptors got removed there's no point in looking for
	 * orphans to process.
	 */
	if (rmcnt == 0)
		orphans = 0;

	/*
	 * Cleanup any alists we've created.
	 */
	remove_collect(ghalp, lmalp);

	/*
	 * If orphan processing isn't required we're done.  If our processing
	 * originated from investigating orphans, return the number of handle
	 * descriptors removed as an indication whether orphan processing
	 * should continue.
	 */
	if (orphans == 0) {
		if (removed)
			*removed = rmcnt;
		return (error);
	}

	/*
	 * Traverse the orphans list as many times as necessary until no
	 * handle removals occur.
	 */
	do {
		APlist		*alp;
		Aliste		idx;
		Grp_hdl		*ghp, *oghp = NULL;
		int		title = 0;

		/*
		 * Effectively clean the HDLIST_ORP list.  Any object that can't
		 * be removed will be re-added to the list.
		 */
		alp = hdl_alp[HDLIST_ORP];
		hdl_alp[HDLIST_ORP] = NULL;

		rescan = 0;
		for (APLIST_TRAVERSE(alp, idx, ghp)) {
			int	_error, _remove;

			if (title++ == 0)
				DBG_CALL(Dbg_file_del_rescan(ghp->gh_ownlml));

			if (oghp) {
				(void) aplist_delete_value(alp, oghp);
				oghp = NULL;
			}

			if (((_error = remove_hdl(ghp, clmp, &_remove)) != 0) &&
			    (error == 0))
				error = _error;

			if (_remove)
				rescan++;

			oghp = ghp;
		}
		if (oghp) {
			(void) aplist_delete_value(alp, oghp);
			oghp = NULL;
		}
		if (alp)
			free((void *)alp);

	} while (rescan && aplist_nitems(hdl_alp[HDLIST_ORP]));

	return (error);
}
