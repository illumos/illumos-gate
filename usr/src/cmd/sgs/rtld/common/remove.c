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
 *
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"_synonyms.h"

#include	<string.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<dlfcn.h>
#include	<sys/debug.h>
#include	<sys/avl.h>
#include	"libc_int.h"
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"debug.h"
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

	/*
	 * Has a callback been established?
	 */
	if (lml->lm_peh == 0)
		return (0);

	/*
	 * Determine the total number of mapped segments that will be unloaded.
	 */
	for (num = 0, _tobj = tobj; *_tobj != NULL; _tobj++) {
		Rt_map *	lmp = *_tobj;

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
	if ((addr = malloc(num * sizeof (Lc_addr_range_t))) == 0)
		return (1);

	/*
	 * Fill the address range with each loadable segments size and address.
	 */
	for (_tobj = tobj, _addr = addr; *_tobj != NULL; _tobj++) {
		Rt_map	*lmp = *_tobj;
		Mmap	*mmaps;

		for (mmaps = MMAPS(lmp); mmaps->m_vaddr; mmaps++) {
			_addr->lb = (void *)mmaps->m_vaddr;
			_addr->ub = (void *)(mmaps->m_vaddr + mmaps->m_msize);
			_addr++;
		}
	}
	_addr->lb = _addr->ub = 0;

	leave(LIST(*tobj));

	error = (* lml->lm_peh)(addr, (num - 1));

	(void) enter();

	/*
	 * If we fail to converse with libc, generate an error message to
	 * satisfy any dlerror() usage.
	 */
	if (error)
		eprintf(ERR_FATAL, MSG_INTL(MSG_ARG_ATEXIT), error);

	free(addr);
	return (error);
}

/*
 * Remove any rejection message allocations.
 */
void
remove_rej(Rej_desc * rej)
{
	if (rej && (rej->rej_type)) {
		if (rej->rej_name)
			free((void *)rej->rej_name);
		if (rej->rej_str && (rej->rej_str != MSG_ORIG(MSG_EMG_ENOMEM)))
			free((void *)rej->rej_str);
	}
}

/*
 * Break down a Pnode list.
 */
void
remove_pnode(Pnode * pnp)
{
	Pnode *	opnp;

	for (opnp = 0; pnp; opnp = pnp, pnp = pnp->p_next) {
		if (pnp->p_name)
			free((void *)pnp->p_name);
		if (pnp->p_oname)
			free((void *)pnp->p_oname);
		if (opnp)
			free((void *)opnp);
	}
	if (opnp)
		free((void *)opnp);
}


/*
 * Remove a link-map list descriptor.  This is called to finalize the removal
 * of an entire link-map list, after all link-maps have been removed, or none
 * got added.  As load_one() can process a list of potential candidates objects,
 * the link-map descriptor must be maintained as each object is processed.  Only
 * after all objects have been processed can a failure condition finally tear
 * down the link-map list descriptor.
 */
void
remove_lml(Lm_list *lml)
{
	if (lml && (lml->lm_head == 0)) {
		if (lml->lm_alp)
			free(lml->lm_alp);
		if (lml->lm_lists)
			free(lml->lm_lists);

		/*
		 * Cleanup rtldinfo in the case where it was allocated but
		 * not called (see _relocate_so()).
		 */
		if (lml->lm_rtldinfo)
			free(lml->lm_rtldinfo);
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

	if (lmp == 0)
		return;

	/*
	 * Unlink the link map from the link-map list.
	 */
	if (lml && lmp)
		lm_delete(lml, lmp);

	/*
	 * If this object contributed the preexec_exit_handler() routine for
	 * the current link-map list, mark the list as no-longer containing a
	 * preexec_exit_handler() routine.
	 */
	if (lml && (lml->lm_peh_lmp == lmp)) {
		lml->lm_peh = 0;
		lml->lm_peh_lmp = 0;
	}

	DBG_CALL(Dbg_file_delete(NAME(lmp)));

	/*
	 * Unmap the object.
	 */
	LM_UNMAP_SO(lmp)(lmp);

	/*
	 * Remove any FullpathNode AVL names if they still exist.
	 */
	if (FPNODE(lmp))
		fpavl_remove(lmp);

	/*
	 * Remove any alias names.
	 */
	if (ALIAS(lmp)) {
		Aliste	off;
		char **	cpp;

		for (ALIST_TRAVERSE(ALIAS(lmp), off, cpp))
			free(*cpp);
		free(ALIAS(lmp));
	}

	/*
	 * Free the various names, as these were duplicated so that they were
	 * available in core files.
	 * The original name is set to the pathname by default (see fullpath()),
	 * but is overridden if the file is an alternative.  The pathname is set
	 * to the name by default (see [aout|elf]_new_lm()), but is overridden
	 * if the fullpath/resolve path differs (see fullpath()).  The original
	 * name is always duplicated, as it typically exists as a text string
	 * (see DT_NEEDED pointer) or was passed in from user code.
	 */
	if (ORIGNAME(lmp) != PATHNAME(lmp))
		free(ORIGNAME(lmp));
	if (PATHNAME(lmp) != NAME(lmp))
		free(PATHNAME(lmp));
	free(NAME(lmp));

	/*
	 * Remove any of this objects filtee infrastructure.  The filtees them-
	 * selves have already been removed.
	 */
	if (((dip = DYNINFO(lmp)) != 0) && (FLAGS1(lmp) & MSK_RT_FILTER)) {
		uint_t	cnt, max = DYNINFOCNT(lmp);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			if (dip->di_info && (dip->di_flags & MSK_DI_FILTER))
				remove_pnode((Pnode *)dip->di_info);
		}
	}
	if (dip)
		free(DYNINFO(lmp));

	/*
	 * Deallocate any remaining cruft and free the link-map.
	 */
	if (RLIST(lmp))
		remove_pnode(RLIST(lmp));

	if (REFNAME(lmp))
		free(REFNAME(lmp));
	if (ELFPRV(lmp))
		free(ELFPRV(lmp));
	if (AUDITORS(lmp))
		audit_desc_cleanup(AUDITORS(lmp), lmp);
	if (AUDINFO(lmp))
		audit_info_cleanup(AUDINFO(lmp));

	if (CONDVAR(lmp))
		free(CONDVAR(lmp));
	if (COPY(lmp))
		free(COPY(lmp));
	if (MMAPS(lmp))
		free(MMAPS(lmp));

	/*
	 * During a dlclose() any groups this object was a part of will have
	 * been torn down.  However, we can get here to remove an object that
	 * has failed to load, perhaps because its addition to a handle failed.
	 * Therefore if this object indicates that its part of a group tear
	 * these associations down.
	 */
	if (GROUPS(lmp)) {
		Aliste		off1;
		Grp_hdl **	ghpp;

		for (ALIST_TRAVERSE(GROUPS(lmp), off1, ghpp)) {
			Grp_hdl *	ghp = *ghpp;
			Grp_desc *	gdp;
			Aliste		off2;

			for (ALIST_TRAVERSE(ghp->gh_depends, off2, gdp)) {
				if (gdp->gd_depend != lmp)
					continue;

				(void) alist_delete(ghp->gh_depends, 0, &off2);
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
	if (reglist != (Reglist *)0) {
		Reglist *	cur, * prv, * del;

		cur = prv = reglist;
		while (cur != (Reglist *)0) {
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

	free(lmp);
}


/*
 * Traverse an objects dependency list removing callers and dependencies.
 * There's a chicken and egg problem with tearing down link-maps.  Any
 * relationship between link-maps is maintained on a DEPENDS, and associated
 * CALLERS list.  These lists can't be broken down at the time a single link-
 * map is removed as any related link-map may have already been removed.  Thus,
 * lists between link-maps must be broken down before the individual link-maps
 * themselves.
 */
void
remove_lists(Rt_map * lmp, int lazy)
{
	Aliste		off1;
	Bnd_desc **	bdpp;

	/*
	 * First, traverse this objects dependencies.
	 */
	for (ALIST_TRAVERSE(DEPENDS(lmp), off1, bdpp)) {
		Bnd_desc *	bdp = *bdpp;
		Rt_map *	dlmp = bdp->b_depend;

		/*
		 * Remove this object from the dependencies callers.
		 */
		(void) alist_delete(CALLERS(dlmp), &bdp, 0);
		free(bdp);
	}
	if (DEPENDS(lmp)) {
		free(DEPENDS(lmp));
		DEPENDS(lmp) = 0;
	}

	/*
	 * Second, traverse this objects callers.
	 */
	for (ALIST_TRAVERSE(CALLERS(lmp), off1,  bdpp)) {
		Bnd_desc *	bdp = *bdpp;
		Rt_map *	clmp = bdp->b_caller;

		/*
		 * If we're removing an object that was triggered by a lazyload,
		 * remove the callers DYNINFO() entry and bump the lazy counts.
		 * This reinitialization of the lazy information allows a lazy
		 * object to be reloaded again later.  Although we may be
		 * breaking down a group of lazyloaded objects because one has
		 * failed to relocate, it's possible that one or more of the
		 * individual objects can be reloaded without a problem.
		 */
		if (lazy) {
			Dyninfo *	dip;

			if ((dip = DYNINFO(clmp)) != 0) {
				uint_t	cnt, max = DYNINFOCNT(clmp);

				for (cnt = 0; cnt < max; cnt++, dip++) {
					if ((dip->di_flags &
					    FLG_DI_NEEDED) == 0)
						continue;

					if (dip->di_info == (void *)lmp) {
						dip->di_info = 0;

						if (LAZY(clmp)++ == 0)
							LIST(clmp)->lm_lazy++;
					}
				}
			}
		}

		(void) alist_delete(DEPENDS(clmp), &bdp, 0);
		free(bdp);
	}
	if (CALLERS(lmp)) {
		free(CALLERS(lmp));
		CALLERS(lmp) = 0;
	}
}

/*
 * Delete any temporary link-map control list.
 */
void
remove_cntl(Lm_list *lml, Aliste lmco)
{
	if (lmco && (lmco != ALO_DATA)) {
		Aliste	_lmco = lmco;
#if	DEBUG
		Lm_cntl	*lmc = (Lm_cntl *)((char *)lml->lm_lists + lmco);

		/*
		 * This element should be empty.
		 */
		ASSERT(lmc->lc_head == 0);
#endif
		(void) alist_delete(lml->lm_lists, 0, &_lmco);
	}
}

/*
 * If a lazy loaded object, or filtee fails to load, possibly because it, or
 * one of its dependencies can't be relocated, then tear down any objects
 * that are apart of this link-map control list.
 */
void
remove_incomplete(Lm_list *lml, Aliste lmco)
{
	Rt_map	*lmp;
	Lm_cntl	*lmc;

	/* LINTED */
	lmc = (Lm_cntl *)((char *)lml->lm_lists + lmco);

	/*
	 * First, remove any lists that may point between objects.
	 */
	for (lmp = lmc->lc_head; lmp; lmp = (Rt_map *)NEXT(lmp))
		remove_lists(lmp, 1);

	/*
	 * Finally, remove each object.  remove_so() calls lm_delete(), thus
	 * effectively the link-map control head gets updated to point to the
	 * next link-map.
	 */
	while ((lmp = lmc->lc_head) != 0)
		remove_so(lml, lmp);

	lmc->lc_head = lmc->lc_tail = 0;
}

/*
 * Determine whether an object is deletable.
 */
int
is_deletable(Alist ** lmalp, Alist ** ghalp, Rt_map * lmp)
{
	Aliste		off;
	Bnd_desc **	bdpp;
	Grp_hdl **	ghpp;

	/*
	 * If the object hasn't yet been relocated take this as a sign that
	 * it's loading failed, thus we're here to cleanup.  If the object is
	 * relocated it will only be retained if it was marked non-deletable,
	 * and exists on the main link-map control list.
	 */
	if ((FLAGS(lmp) & FLG_RT_RELOCED) &&
	    (MODE(lmp) & RTLD_NODELETE) && (CNTL(lmp) == ALO_DATA))
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
	for (ALIST_TRAVERSE(HANDLES(lmp), off, ghpp)) {
		if (alist_test(ghalp, *ghpp,
		    sizeof (Grp_hdl *), 0) != ALE_EXISTS)
			return (0);
	}

	/*
	 * If this object is called by any object outside of the family of
	 * objects selected for deletion, it can't be deleted.
	 */
	for (ALIST_TRAVERSE(CALLERS(lmp), off, bdpp)) {
		if (alist_test(lmalp, (*bdpp)->b_caller,
		    sizeof (Rt_map *), 0) != ALE_EXISTS)
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
gdp_collect(Alist ** ghalpp, Alist ** lmalpp, Grp_hdl * ghp1)
{
	Aliste		off;
	Grp_desc *	gdp;
	int		action;

	/*
	 * Add this group to our group collection.  If it isn't added either an
	 * allocation has failed, or it already exists.
	 */
	if ((action = alist_test(ghalpp, ghp1, sizeof (Grp_hdl *),
	    AL_CNT_GRPCLCT)) != ALE_CREATE)
		return (action);

	/*
	 * Traverse the dependencies of the group and collect the associated
	 * objects.
	 */
	for (ALIST_TRAVERSE(ghp1->gh_depends, off, gdp)) {
		Rt_map *	lmp = gdp->gd_depend;

		/*
		 * We only want to process dependencies for deletion.  Although
		 * we want to purge group descriptors for parents, we don't want
		 * to analyze the parent itself for additional filters or
		 * deletion.
		 */
		if ((gdp->gd_flags & GPD_ADDEPS) == 0)
			continue;

		if ((action = alist_test(lmalpp, lmp, sizeof (Rt_map *),
		    AL_CNT_GRPCLCT)) == 0)
			return (0);
		if (action == ALE_EXISTS)
			continue;

		/*
		 * If this object hasn't yet been relocated take this as a sign
		 * that it's loading failed, thus we're here to cleanup.  Or,
		 * if this object isn't obviously non-deletable, determine
		 * whether it provides any filtees.  Add these groups to the
		 * group collection.
		 */
		if ((((FLAGS(lmp) & FLG_RT_RELOCED) == 0) ||
		    ((MODE(lmp) & RTLD_NODELETE) == 0)) &&
		    (FLAGS1(lmp) & MSK_RT_FILTER)) {
			Dyninfo *	dip = DYNINFO(lmp);
			uint_t		cnt, max = DYNINFOCNT(lmp);

			for (cnt = 0; cnt < max; cnt++, dip++) {
				Pnode *	pnp;

				if ((dip->di_info == 0) ||
				    ((dip->di_flags & MSK_DI_FILTER) == 0))
					continue;

				for (pnp = (Pnode *)dip->di_info; pnp;
				    pnp = pnp->p_next) {
					Grp_hdl *	ghp2;

					if ((pnp->p_len == 0) || ((ghp2 =
					    (Grp_hdl *)pnp->p_info) == 0))
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
remove_rescan(Alist * lmalp, Alist * ghalp, int *delcnt)
{
	Aliste		off1;
	Rt_map **	lmpp;
	int		rescan = 0;

	for (ALIST_TRAVERSE(lmalp, off1, lmpp)) {
		Aliste		off2;
		Bnd_desc **	bdpp;
		Rt_map *	lmp = *lmpp;
		Dyninfo *	dip;
		uint_t		cnt, max;

		if (FLAGS(lmp) & FLG_RT_DELETE)
			continue;

		/*
		 * As this object can't be deleted, make sure its dependencies
		 * aren't deleted either.
		 */
		for (ALIST_TRAVERSE(DEPENDS(lmp), off2, bdpp)) {
			Rt_map *	dlmp = (*bdpp)->b_depend;

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
			Pnode *	pnp;

			if ((dip->di_info == 0) ||
			    ((dip->di_flags & MSK_DI_FILTER) == 0))
				continue;

			for (pnp = (Pnode *)dip->di_info; pnp;
			    pnp = pnp->p_next) {
				Grp_hdl *	ghp;
				Grp_desc *	gdp;

				if ((pnp->p_len == 0) ||
				    ((ghp = (Grp_hdl *)pnp->p_info) == 0))
					continue;

				if (alist_test(&ghalp, ghp,
				    sizeof (Grp_hdl *), 0) == ALE_EXISTS)
					continue;

				for (ALIST_TRAVERSE(ghp->gh_depends, off2,
				    gdp)) {
					Rt_map *	dlmp = gdp->gd_depend;

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
				(void) alist_delete(ghalp, &ghp, 0);
			}
		}
	}
	return (rescan);
}

/*
 * Cleanup any collection alists we've created.
 */
static void
remove_collect(Alist * ghalp, Alist * lmalp)
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
free_hdl(Grp_hdl *ghp)
{
	if (--(ghp->gh_refcnt) == 0) {
		Grp_desc	*gdp;
		uintptr_t	ndx;
		Aliste		off;

		for (ALIST_TRAVERSE(ghp->gh_depends, off, gdp)) {
			Rt_map	*lmp = gdp->gd_depend;

			if (ghp->gh_owner == lmp)
				(void) alist_delete(HANDLES(lmp), &ghp, 0);
			(void) alist_delete(GROUPS(lmp), &ghp, 0);
		}
		(void) free(ghp->gh_depends);

		/* LINTED */
		ndx = (uintptr_t)ghp % HDLIST_SZ;
		list_delete(&hdl_list[ndx], ghp);

		(void) free(ghp);
	}
}

/*
 * Remove a caller from a group handle.  This breaks the bond between a caller
 * and a hierarchy of dependencies represented by a handle, thus the caller
 * doesn't lock the hierarchy and prevent their deletion should their processing
 * fail to complete.  If the handle count drops to zero, the handle is marked
 * as sticky to prevent it's removal, or to confuse orphan handle processing.
 * The caller may establish a binding to this handle again, once the hierarchy
 * processing has completed, thus retaining the handle saves having to recreate
 * it over and over again.
 */
void
remove_caller(Grp_hdl *ghp, Rt_map *clmp)
{
	Grp_desc	*gdp;
	Aliste		off;

	if (--(ghp->gh_refcnt) == 0)
		ghp->gh_flags |= GPH_STICKY;

	for (ALIST_TRAVERSE(ghp->gh_depends, off, gdp)) {
		Rt_map	*lmp = gdp->gd_depend;

		if (lmp == clmp) {
			(void) alist_delete(GROUPS(lmp), &ghp, 0);
			(void) alist_delete(ghp->gh_depends, 0, &off);
			break;
		}
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
remove_hdl(Grp_hdl * ghp, Rt_map * clmp, int *removed)
{
	Rt_map *	lmp, ** lmpp;
	int		rescan = 0;
	int		delcnt = 0, rmcnt = 0, error = 0, orphans;
	Alist *		lmalp = 0, * ghalp = 0;
	Aliste		off1, off2;
	Grp_hdl **	ghpp;
	Grp_desc *	gdp;
	Lm_list *	lml = 0;

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

	DBG_CALL(Dbg_file_hdl_title(DBG_DEP_DELETE));

	/*
	 * Traverse the groups we've collected to determine if any filtees are
	 * included.  If so, and the filtee handle is in use by a filter outside
	 * of the family of objects collected for this deletion, it can not be
	 * removed.
	 */
	for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
		Grp_hdl *	ghp = *ghpp;

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
			(void) alist_delete(ghalp, 0, &off1);
			continue;
		}

		for (ALIST_TRAVERSE(ghp->gh_depends, off2, gdp)) {
			Grp_hdl **	ghpp3;
			Aliste		off3;

			/*
			 * Determine whether this dependency is the filtee's
			 * parent filter, and that it isn't also an explicit
			 * dependency (in which case it would have added its own
			 * dependencies to the handle).
			 */
			if ((gdp->gd_flags &
			    (GPD_FILTER | GPD_ADDEPS)) != GPD_FILTER)
				continue;

			if (alist_test(&lmalp, gdp->gd_depend,
			    sizeof (Rt_map *), 0) == ALE_EXISTS)
				continue;

			/*
			 * Remove this group handle from our dynamic deletion
			 * list.  In addition, recompute the list of objects
			 * that are candidates for deletion to continue this
			 * group verification.
			 */
			DBG_CALL(Dbg_file_hdl_collect(ghp,
			    NAME(gdp->gd_depend)));
			(void) alist_delete(ghalp, 0, &off1);

			free(lmalp);
			lmalp = 0;
			for (ALIST_TRAVERSE(ghalp, off3, ghpp3)) {
				Aliste		off4;
				Grp_desc *	gdp4;

				for (ALIST_TRAVERSE((*ghpp3)->gh_depends,
				    off4, gdp4))  {
					if ((gdp4->gd_flags & GPD_ADDEPS) == 0)
						continue;
					if (alist_test(&lmalp, gdp4->gd_depend,
					    sizeof (Rt_map *),
					    AL_CNT_GRPCLCT) == 0) {
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
	for (ALIST_TRAVERSE(lmalp, off1, lmpp)) {
		lmp = *lmpp;

		/*
		 * Establish which link-map list we're dealing with for later
		 * .fini processing.
		 */
		if (lml == 0)
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
	for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
		for (ALIST_TRAVERSE((*ghpp)->gh_depends, off2, gdp))
			gdp->gd_flags |= GPD_REMOVE;
	}

	/*
	 * Now that we know which objects on this handle can't be deleted
	 * determine whether they still need to remain identified as belonging
	 * to this group to be able to continue binding to one another.
	 */
	for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
		Grp_hdl *	ghp = *ghpp;

		for (ALIST_TRAVERSE(ghp->gh_depends, off2, gdp)) {
			Aliste		off3;
			Bnd_desc **	bdpp;

			lmp = gdp->gd_depend;

			if (FLAGS(lmp) & FLG_RT_DELETE)
				continue;

			for (ALIST_TRAVERSE(DEPENDS(lmp), off3, bdpp)) {
				Aliste 		off4;
				Grp_desc *	gdp4;
				Rt_map *	dlmp = (*bdpp)->b_depend;

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
				if ((callable(lmp, dlmp, 0) == 0) ||
				    callable(lmp, dlmp, ghp))
					continue;

				if (gdp->gd_flags & GPD_REMOVE)
					gdp->gd_flags &= ~GPD_REMOVE;

				for (ALIST_TRAVERSE(ghp->gh_depends,
				    off4, gdp4)) {
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
	for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
		Grp_hdl *	ghp = *ghpp;

		/*
		 * If this handle is already an orphan, or if it's owner is
		 * deletable there's no need to inspect its dependencies.
		 */
		if ((ghp->gh_owner == 0) ||
		    (FLAGS(ghp->gh_owner) & FLG_RT_DELETE))
			continue;

		/*
		 * Make sure all handle dependencies aren't removed or the
		 * dependencies themselves aren't deleted.
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, off2, gdp)) {
			lmp = gdp->gd_depend;

			/*
			 * The first dependency of a non-orphaned handle is the
			 * owner.  If the handle descriptor for this isn't
			 * required there's no need to look at any other of the
			 * handles dependencies.
			 */
			if ((lmp == ghp->gh_owner) &&
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
	for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
		Grp_hdl *	ghp = *ghpp;

		DBG_CALL(Dbg_file_hdl_title(DBG_DEP_DELETE));

		for (ALIST_TRAVERSE(ghp->gh_depends, off2, gdp)) {
			int	flag;

			lmp = gdp->gd_depend;

			if (FLAGS(lmp) & FLG_RT_DELETE) {
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

			DBG_CALL(Dbg_file_hdl_action(ghp, lmp, flag));
		}
	}

	/*
	 * If there are objects to be deleted process their .fini's.
	 */
	if (delcnt) {
		Rt_map **	tobj;

		/*
		 * If we're being audited tell the audit library that we're
		 * about to go deleting dependencies.
		 */
		if (clmp && ((LIST(clmp)->lm_tflags | FLAGS1(clmp)) &
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
		    (RT_SORT_DELETE | RT_SORT_FWD))) != 0) &&
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
		for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
			Grp_hdl *	ghp = *ghpp;
			Rt_map *	dlmp = ghp->gh_owner;

			if (clmp && dlmp &&
			    ((LIST(dlmp)->lm_flags & LML_FLG_NOAUDIT) == 0) &&
			    (FLAGS1(clmp) & LML_TFLG_AUD_OBJCLOSE))
				_audit_objclose(&(AUDITORS(clmp)->ad_list),
				    dlmp);
		}
	}

	/*
	 * Now that .fini processing (which may have involved new bindings)
	 * is complete, remove all inter-dependency lists from those objects
	 * selected for deletion.
	 */
	for (ALIST_TRAVERSE(lmalp, off1, lmpp)) {
		Dyninfo *	dip;
		uint_t		cnt, max;

		lmp = *lmpp;

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
			Pnode *	pnp;

			if ((dip->di_info == 0) ||
			    ((dip->di_flags & MSK_DI_FILTER) == 0))
				continue;

			for (pnp = (Pnode *)dip->di_info; pnp;
			    pnp = pnp->p_next) {
				Grp_hdl *	ghp;

				if ((pnp->p_len == 0) ||
				    ((ghp = (Grp_hdl *)pnp->p_info) == 0))
					continue;

				/*
				 * Determine whether this filtee's handle is a
				 * part of the list of handles being deleted.
				 */
				if (alist_test(&ghalp, ghp,
				    sizeof (Grp_hdl *), 0) == ALE_EXISTS) {
					/*
					 * If this handle exists on the deletion
					 * list, then it has been removed.  If
					 * this filter isn't going to be
					 * deleted, server its reference to the
					 * handle.
					 */
					pnp->p_info = 0;
				} else {
					/*
					 * If this handle isn't on the deletion
					 * list, then it must still exist.  If
					 * this filter is being deleted, make
					 * sure the filtees reference count
					 * gets decremented.
					 */
					if (FLAGS(lmp) & FLG_RT_DELETE)
					    (void) dlclose_core(ghp, lmp);
				}
			}
		}
	}

	/*
	 * If called from dlclose(), determine if there are already handles on
	 * the orphans list that we can reinvestigate.
	 */
	if ((removed == 0) && hdl_list[HDLIST_ORP].head)
		orphans = 1;
	else
		orphans = 0;

	/*
	 * Finally remove any handle infrastructure and remove any objects
	 * marked for deletion.
	 */
	for (ALIST_TRAVERSE(ghalp, off1, ghpp)) {
		Grp_hdl *	ghp = *ghpp;

		/*
		 * If we're not dealing with orphaned handles remove this handle
		 * from its present handle list.
		 */
		if (removed == 0) {
			uintptr_t ndx;

			/* LINTED */
			ndx = (uintptr_t)ghp % HDLIST_SZ;
			list_delete(&hdl_list[ndx], ghp);
		}

		/*
		 * Traverse each handle dependency.
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, off2, gdp)) {
			if ((gdp->gd_flags & GPD_REMOVE) == 0)
				continue;

			lmp = gdp->gd_depend;
			rmcnt++;

			/*
			 * If this object is the owner of the handle break that
			 * association in case the handle is retained.
			 */
			if (ghp->gh_owner == lmp) {
				(void) alist_delete(HANDLES(lmp), &ghp, 0);
				ghp->gh_owner = 0;
			}

			(void) alist_delete(GROUPS(lmp), &ghp, 0);
			(void) alist_delete(ghp->gh_depends, 0, &off2);

			/*
			 * Complete the link-map deletion if appropriate.
			 */
			if (FLAGS(lmp) & FLG_RT_DELETE) {
				tls_modactivity(lmp, TM_FLG_MODREM);
				remove_so(LIST(lmp), lmp);
			}
		}

		/*
		 * If we've deleted all the dependencies of the handle finalize
		 * the cleanup by removing the handle itself.
		 *
		 * Otherwise we're left with a handle containing one or more
		 * objects that can not be deleted (they're in use by other
		 * handles, non-deletable, etc.), but require to remain a part
		 * of this group to allow them to continue binding to one
		 * another.  Should any other dlclose() operation occur that
		 * results in the removal of handle descriptors, these orphan
		 * handles are re-examined to determine if their deletion can be
		 * completed.
		 */
		if (ghp->gh_depends->al_data[0] == 0) {
			remove_lml(lml);
			free(ghp->gh_depends);
			free(ghp);
		} else if (removed == 0) {
			/*
			 * Move this handle to the orphans list (if it isn't
			 * already there).
			 */
			(void) list_append(&hdl_list[HDLIST_ORP], ghp);

			if (dbg_mask) {
				DBG_CALL(Dbg_file_hdl_title(DBG_DEP_ORPHAN));
				for (ALIST_TRAVERSE(ghp->gh_depends, off1, gdp))
					DBG_CALL(Dbg_file_hdl_action(ghp,
					    gdp->gd_depend, DBG_DEP_REMAIN));
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
		List		list;
		Listnode *	lnp;
		Grp_hdl *	ghp, * oghp = 0;

		DBG_CALL(Dbg_file_del_rescan());

		/*
		 * Effectively clean the HDLIST_ORP list.  Any object that can't
		 * be removed will be re-added to the list.
		 */
		list = hdl_list[HDLIST_ORP];
		hdl_list[HDLIST_ORP].head = hdl_list[HDLIST_ORP].tail = 0;

		rescan = 0;
		for (LIST_TRAVERSE(&list, lnp, ghp)) {
			int	_error, _remove;

			if (oghp) {
				list_delete(&list, oghp);
				oghp = 0;
			}

			if (((_error = remove_hdl(ghp, clmp, &_remove)) != 0) &&
			    (error == 0))
				error = _error;

			if (_remove)
				rescan++;

			oghp = ghp;
		}
		if (oghp) {
			list_delete(&list, oghp);
			oghp = 0;
		}

	} while (rescan && hdl_list[HDLIST_ORP].head);

	return (error);
}
