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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Programmatic interface to the run_time linker.
 */
#include	"_synonyms.h"

#include	<sys/debug.h>
#include	<stdio.h>
#include	<string.h>
#include	<dlfcn.h>
#include	<synch.h>
#include	<limits.h>
#include	<debug.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

/*
 * Determine who called us - given a pc determine in which object it resides.
 *
 * For dlopen() the link map of the caller must be passed to load_so() so that
 * the appropriate search rules (4.x or 5.0) are used to locate any
 * dependencies.  Also, if we've been called from a 4.x module it may be
 * necessary to fix the specified pathname so that it conforms with the 5.0 elf
 * rules.
 *
 * For dlsym() the link map of the caller is used to determine RTLD_NEXT
 * requests, together with requests based off of a dlopen(0).
 * For dladdr() this routines provides a generic means of scanning all loaded
 * segments.
 */
Rt_map *
_caller(caddr_t cpc, int flags)
{
	Lm_list *	lml;
	Listnode *	lnp;

	for (LIST_TRAVERSE(&dynlm_list, lnp, lml)) {
		Aliste	idx;
		Lm_cntl	*lmc;

		for (ALIST_TRAVERSE(lml->lm_lists, idx, lmc)) {
			Rt_map	*lmp;

			for (lmp = lmc->lc_head; lmp;
			    lmp = (Rt_map *)NEXT(lmp)) {
				Mmap	*mmap;

				/*
				 * Traverse this objects mappings testing
				 * whether the pc falls within its range.
				 */
				for (mmap = MMAPS(lmp); mmap->m_vaddr; mmap++) {
					if ((cpc >= mmap->m_vaddr) && (cpc <
					    (mmap->m_vaddr + mmap->m_msize)))
						return (lmp);
				}
			}
		}
	}

	/*
	 * No mapping can be determined.  If asked for a default, assume this
	 * is from the executable.
	 */
	if (flags & CL_EXECDEF)
		return ((Rt_map *)lml_main.lm_head);

	return (0);
}

#pragma weak dlerror = _dlerror

/*
 * External entry for dlerror(3dl).  Returns a pointer to the string describing
 * the last occurring error.  The last occurring error is cleared.
 */
char *
_dlerror()
{
	char	*error;
	Rt_map	*clmp;
	int	entry;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);

	error = lasterr;
	lasterr = (char *)0;

	if (entry)
		leave(LIST(clmp));
	return (error);
}

/*
 * Add a dependency as a group descriptor to a group handle.  Returns 0 on
 * failure, ALE_EXISTS if the dependency already exists, or ALE_CREATE if it
 * is newly created.
 */
int
hdl_add(Grp_hdl *ghp, Rt_map *lmp, uint_t flags)
{
	Grp_desc	*gdp;
	Aliste		idx;
	int		found = ALE_CREATE;
	uint_t		oflags;

	/*
	 * Make sure this dependency hasn't already been recorded.
	 */
	for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
		if (gdp->gd_depend == lmp) {
			found = ALE_EXISTS;
			break;
		}
	}

	if (found == ALE_CREATE) {
		Grp_desc	gd;

		/*
		 * Create a new handle descriptor.
		 */
		gd.gd_depend = lmp;
		gd.gd_flags = 0;

		/*
		 * Indicate this object is a part of this handles group.
		 */
		if (aplist_append(&GROUPS(lmp), ghp,
		    AL_CNT_GROUPS) == 0)
			return (0);

		/*
		 * Append the new dependency to this handle.
		 */
		if ((gdp = alist_append(&ghp->gh_depends, &gd,
		    sizeof (Grp_desc), AL_CNT_DEPENDS)) == 0)
			return (0);
	}

	oflags = gdp->gd_flags;
	gdp->gd_flags |= flags;

	if (DBG_ENABLED) {
		if (found == ALE_CREATE)
			DBG_CALL(Dbg_file_hdl_action(ghp, lmp, DBG_DEP_ADD,
			    gdp->gd_flags));
		else if (gdp->gd_flags != oflags)
			DBG_CALL(Dbg_file_hdl_action(ghp, lmp, DBG_DEP_UPDATE,
			    gdp->gd_flags));
	}
	return (found);
}

/*
 * Allocate a handle and record its existence on the handle list for future
 * verification.
 */
Grp_hdl *
hdl_alloc()
{
	Grp_hdl	*ghp;
	uint_t	ndx;

	if ((ghp = calloc(sizeof (Grp_hdl), 1)) == 0)
		return (0);

	/* LINTED */
	ndx = (uintptr_t)ghp % HDLIST_SZ;

	if (list_append(&hdl_list[ndx], ghp) == 0) {
		free(ghp);
		return (0);
	}
	return (ghp);
}

/*
 * Create a handle.
 */
Grp_hdl *
hdl_create(Lm_list *lml, Rt_map *nlmp, Rt_map *clmp, uint_t hflags,
    uint_t ndflags, uint_t cdflags)
{
	Grp_hdl	*ghp = 0, *_ghp;
	APlist	**alpp;
	Aliste	idx;

	/*
	 * For dlopen(0) the handle is maintained as part of the link-map list,
	 * otherwise it is associated with the referenced link-map.
	 */
	if (hflags & GPH_ZERO)
		alpp = &(lml->lm_handle);
	else
		alpp = &(HANDLES(nlmp));

	/*
	 * Objects can contain multiple handles depending on the handle flags
	 * supplied.  Most RTLD flags pertain to the object itself and the
	 * bindings that it can achieve.  Multiple handles for these flags
	 * don't make sense.  But if the flag determines how the handle might
	 * be used, then multiple handles may exist.  Presently this only makes
	 * sense for RTLD_FIRST.  Determine if an appropriate handle already
	 * exists.
	 */
	for (APLIST_TRAVERSE(*alpp, idx, _ghp)) {
		if ((_ghp->gh_flags & GPH_FIRST) == (hflags & GPH_FIRST)) {
			ghp = _ghp;
			break;
		}
	}

	if (ghp == 0) {
		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_CREATE));

		/*
		 * If this is the first dlopen() request for this handle
		 * allocate and initialize a new handle.
		 */
		if ((ghp = hdl_alloc()) == 0)
			return (0);

		if (aplist_append(alpp, ghp, AL_CNT_GROUPS) == 0)
			return (0);

		/*
		 * Indicate that this object has been referenced.  In truth a
		 * reference hasn't yet occurred, it's a dlsym() that makes the
		 * reference.  However, we assume that anyone performing a
		 * dlopen() will eventually call dlsym(), plus this makes for a
		 * better diagnostic location rather than having to call
		 * unused() after every dlsym() operation.
		 */
		if (nlmp)
			FLAGS1(nlmp) |= FL1_RT_USED;

		ghp->gh_refcnt = 1;
		ghp->gh_flags = hflags;

		/*
		 * A dlopen(0) handle is identified by the GPH_ZERO flag, the
		 * head of the link-map list is defined as the owner.  There is
		 * no need to maintain a list of dependencies, for when this
		 * handle is used (for dlsym()) a dynamic search through the
		 * entire link-map list provides for searching all objects with
		 * GLOBAL visibility.
		 */
		if (hflags & GPH_ZERO) {
			ghp->gh_ownlmp = lml->lm_head;
			ghp->gh_ownlml = lml;
		} else {
			ghp->gh_ownlmp = nlmp;
			ghp->gh_ownlml = LIST(nlmp);

			if (hdl_add(ghp, nlmp, ndflags) == 0)
				return (0);

			/*
			 * Indicate that a local group now exists.  This state
			 * allows singleton searches to be optimized.
			 */
			if ((hflags & GPH_LDSO) == 0)
				LIST(nlmp)->lm_flags |= LML_FLG_GROUPSEXIST;
		}
	} else {
		/*
		 * If a handle already exists, bump its reference count.
		 *
		 * If the previous reference count was 0, then this is a handle
		 * that an earlier call to dlclose() was unable to remove.  Such
		 * handles are put on the orphan list.  As this handle is back
		 * in use, it must be removed from the orphan list.
		 *
		 * Note, handles associated with a link-map list itself (i.e.
		 * dlopen(0)) can have a reference count of 0.  However, these
		 * handles are never deleted, and therefore are never moved to
		 * the orphan list.
		 */
		if ((ghp->gh_refcnt++ == 0) &&
		    ((ghp->gh_flags & GPH_ZERO) == 0)) {
			uint_t	ndx;

			/* LINTED */
			ndx = (uintptr_t)ghp % HDLIST_SZ;

			list_delete(&hdl_list[HDLIST_ORP], ghp);
			(void) list_append(&hdl_list[ndx], ghp);

			if (DBG_ENABLED) {
				Aliste		idx;
				Grp_desc	*gdp;

				DBG_CALL(Dbg_file_hdl_title(DBG_HDL_REINST));
				for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp))
					DBG_CALL(Dbg_file_hdl_action(ghp,
					    gdp->gd_depend, DBG_DEP_REINST, 0));
			}
		}
	}

	/*
	 * Keep track of the parent (caller).  As this object could be opened
	 * by different parents, this processing is carried out every time a
	 * handle is requested.
	 */
	if (clmp && (hdl_add(ghp, clmp, cdflags) == 0))
		return (0);

	return (ghp);
}

/*
 * Initialize a handle that has been created for an object that is already
 * loaded.  The handle is initialized with the present dependencies of that
 * object.  Once this initialization has occurred, any new objects that might
 * be loaded as dependencies (lazy-loading) are added to the handle as each new
 * object is loaded.
 */
int
hdl_initialize(Grp_hdl *ghp, Rt_map *nlmp, int mode, int promote)
{
	Aliste		idx;
	Grp_desc	*gdp;

	/*
	 * If the handle has already been initialized, and the initial object's
	 * mode hasn't been promoted, there's no need to recompute the modes of
	 * any dependencies.  If the object we've added has just been opened,
	 * the objects dependencies will not yet have been processed.  These
	 * dependencies will be added on later calls to load_one().  Otherwise,
	 * this object already exists, so add all of its dependencies to the
	 * handle were operating on.
	 */
	if (((ghp->gh_flags & GPH_INITIAL) && (promote == 0)) ||
	    ((FLAGS(nlmp) & FLG_RT_ANALYZED) == 0)) {
		ghp->gh_flags |= GPH_INITIAL;
		return (1);
	}

	DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
	for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
		Rt_map *	lmp = gdp->gd_depend;
		Aliste		idx1;
		Bnd_desc	*bdp;

		/*
		 * If this dependency doesn't indicate that its dependencies
		 * should be added to a handle, ignore it.  This case identifies
		 * a parent of a dlopen(RTLD_PARENT) request.
		 */
		if ((gdp->gd_flags & GPD_ADDEPS) == 0)
			continue;

		for (APLIST_TRAVERSE(DEPENDS(lmp), idx1, bdp)) {
			Rt_map		*dlmp = bdp->b_depend;

			if ((bdp->b_flags & BND_NEEDED) == 0)
				continue;

			if (hdl_add(ghp, dlmp,
			    (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS)) == 0)
				return (0);

			(void) update_mode(dlmp, MODE(dlmp), mode);
		}
	}
	ghp->gh_flags |= GPH_INITIAL;
	return (1);
}

/*
 * Sanity check a program-provided handle.
 */
static int
hdl_validate(Grp_hdl *ghp)
{
	Listnode	*lnp;
	Grp_hdl		*lghp;
	uint_t		ndx;

	/* LINTED */
	ndx = (uintptr_t)ghp % HDLIST_SZ;

	for (LIST_TRAVERSE(&hdl_list[ndx], lnp, lghp)) {
		if ((lghp == ghp) && (ghp->gh_refcnt != 0))
			return (1);
	}
	return (0);
}

/*
 * Core dlclose activity.
 */
int
dlclose_core(Grp_hdl *ghp, Rt_map *clmp, Lm_list *lml)
{
	int	error;

	/*
	 * If we're already at atexit() there's no point processing further,
	 * all objects have already been tsorted for fini processing.
	 */
	if ((rtld_flags & RT_FL_ATEXIT) != 0)
		return (0);

	/*
	 * Diagnose what we're up to.
	 */
	if (ghp->gh_flags & GPH_ZERO) {
		DBG_CALL(Dbg_file_dlclose(LIST(clmp), MSG_ORIG(MSG_STR_ZERO),
		    DBG_DLCLOSE_IGNORE));
	} else {
		DBG_CALL(Dbg_file_dlclose(LIST(clmp), NAME(ghp->gh_ownlmp),
		    DBG_DLCLOSE_NULL));
	}


	/*
	 * Decrement reference count of this object.
	 */
	if (--(ghp->gh_refcnt))
		return (0);

	/*
	 * If this handle is special (dlopen(0)), then leave it around - it
	 * has little overhead.
	 */
	if (ghp->gh_flags & GPH_ZERO)
		return (0);

	/*
	 * This handle is no longer being referenced, remove it.  If this handle
	 * is part of an alternative link-map list, determine if the whole list
	 * can be removed also.
	 */
	error = remove_hdl(ghp, clmp, 0);

	if ((lml->lm_flags & (LML_FLG_BASELM | LML_FLG_RTLDLM)) == 0)
		remove_lml(lml);

	return (error);
}

/*
 * Internal dlclose activity.  Called from user level or directly for internal
 * error cleanup.
 */
int
dlclose_intn(Grp_hdl *ghp, Rt_map *clmp)
{
	Rt_map	*nlmp = 0;
	Lm_list	*olml = 0;
	int	error;

	/*
	 * Although we're deleting object(s) it's quite possible that additional
	 * objects get loaded from running the .fini section(s) of the objects
	 * being deleted.  These objects will have been added to the same
	 * link-map list as those objects being deleted.  Remember this list
	 * for later investigation.
	 */
	olml = ghp->gh_ownlml;

	error = dlclose_core(ghp, clmp, olml);

	/*
	 * Determine whether the original link-map list still exists.  In the
	 * case of a dlclose of an alternative (dlmopen) link-map the whole
	 * list may have been removed.
	 */
	if (olml) {
		Listnode	*lnp;
		Lm_list		*lml;

		for (LIST_TRAVERSE(&dynlm_list, lnp, lml)) {
			if (olml == lml) {
				nlmp = olml->lm_head;
				break;
			}
		}
	}
	load_completion(nlmp);
	return (error);
}

/*
 * Argument checking for dlclose.  Only called via external entry.
 */
static int
dlclose_check(void *handle, Rt_map *clmp)
{
	Grp_hdl	*ghp = (Grp_hdl *)handle;

	if (hdl_validate(ghp) == 0) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_INVHNDL));
		return (1);
	}
	return (dlclose_intn(ghp, clmp));
}

#pragma weak dlclose = _dlclose

/*
 * External entry for dlclose(3dl).  Returns 0 for success, non-zero otherwise.
 */
int
_dlclose(void *handle)
{
	int		error, entry;
	Rt_map		*clmp;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);

	error = dlclose_check(handle, clmp);

	if (entry)
		leave(LIST(clmp));
	return (error);
}

static uint_t	lmid = 0;

/*
 * The addition of new link-map lists is assumed to be in small quantities.
 * Here, we assign a unique link-map id for diagnostic use.  Simply update the
 * running link-map count until we max out.
 */
int
newlmid(Lm_list *lml)
{
	char	buffer[MSG_LMID_ALT_SIZE + 12];

	if (lmid == UINT_MAX) {
		lml->lm_lmid = UINT_MAX;
		(void) strncpy(buffer, MSG_ORIG(MSG_LMID_MAXED),
		    MSG_LMID_ALT_SIZE + 12);
	} else {
		lml->lm_lmid = lmid++;
		(void) snprintf(buffer, MSG_LMID_ALT_SIZE + 12,
		    MSG_ORIG(MSG_LMID_FMT), MSG_ORIG(MSG_LMID_ALT),
		    lml->lm_lmid);
	}
	if ((lml->lm_lmidstr = strdup(buffer)) == 0)
		return (0);

	return (1);
}

/*
 * Core dlopen activity.
 */
static Grp_hdl *
dlmopen_core(Lm_list *lml, const char *path, int mode, Rt_map *clmp,
    uint_t flags, uint_t orig)
{
	Rt_map	*nlmp;
	Grp_hdl	*ghp;
	Pnode	*pnp;
	Aliste	olmco, nlmco;
	Lm_cntl	*lmc;

	DBG_CALL(Dbg_file_dlopen(clmp,
	    (path ? path : MSG_ORIG(MSG_STR_ZERO)), mode));

	/*
	 * If the path specified is null then we're operating on global
	 * objects.  Associate a dummy handle with the link-map list.
	 */
	if (path == 0) {
		Grp_hdl *ghp;
		uint_t	hflags = GPH_ZERO, cdflags = GPD_PARENT;
		int	promote = 0;

		/*
		 * Establish any flags for the handle (Grp_hdl).
		 *
		 *  .	This is a dummy handle (0) that provides for a dynamic
		 *	search of all global objects within the process.
		 *
		 *  .   Use of the RTLD_FIRST flag indicates that only the first
		 *	dependency on the handle (the new object) can be used
		 *	to satisfy dlsym() requests.
		 */
		if (mode & RTLD_FIRST)
			hflags |= GPH_FIRST;

		/*
		 * Establish the flags for this callers dependency descriptor
		 * (Grp_desc).
		 *
		 *  .	The explicit creation of a handle creates a descriptor
		 *	for the new object and the parent (caller),
		 *
		 *  .	Use of the RTLD_PARENT flag indicates that the parent
		 *	can be relocated against.
		 */
		if (mode & RTLD_PARENT)
			cdflags |= GPD_RELOC;

		if ((ghp = hdl_create(lml, 0, clmp, hflags,
		    (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS), cdflags)) == 0)
			return (0);

		/*
		 * Traverse the main link-map control list, updating the mode
		 * of any objects as necessary.  Call the relocation engine if
		 * this mode promotes the existing state of any relocations.
		 * crle()'s first pass loads all objects necessary for building
		 * a configuration file, however none of them are relocated.
		 * crle()'s second pass relocates objects in preparation for
		 * dldump()'ing using dlopen(0, RTLD_NOW).
		 */
		if ((mode & (RTLD_NOW | RTLD_CONFGEN)) == RTLD_CONFGEN)
			return (ghp);

		for (nlmp = lml->lm_head; nlmp; nlmp = (Rt_map *)NEXT(nlmp)) {
			if (((MODE(nlmp) & RTLD_GLOBAL) == 0) ||
			    (FLAGS(nlmp) & FLG_RT_DELETE))
				continue;

			if (update_mode(nlmp, MODE(nlmp), mode))
				promote = 1;
		}
		if (promote)
			(void) relocate_lmc(lml, ALIST_OFF_DATA, clmp,
			    lml->lm_head);

		return (ghp);
	}

	/*
	 * Fix the pathname.  If this object expands to multiple paths (ie.
	 * $ISALIST or $HWCAP have been used), then make sure the user has also
	 * furnished the RTLD_FIRST flag.  As yet, we don't support opening
	 * more than one object at a time, so enforcing the RTLD_FIRST flag
	 * provides flexibility should we be able to support dlopening more
	 * than one object in the future.
	 */
	if ((pnp = LM_FIX_NAME(clmp)(path, clmp, orig)) == 0)
		return (0);

	if (((pnp->p_orig & (PN_TKN_ISALIST | PN_TKN_HWCAP)) || pnp->p_next) &&
	    ((mode & RTLD_FIRST) == 0)) {
		remove_pnode(pnp);
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_5));
		return (0);
	}

	/*
	 * Create a new link-map control list for this request, and load the
	 * associated object.
	 */
	if ((lmc = alist_append(&lml->lm_lists, 0, sizeof (Lm_cntl),
	    AL_CNT_LMLISTS)) == 0) {
		remove_pnode(pnp);
		return (0);
	}
	olmco = nlmco = (Aliste)((char *)lmc - (char *)lml->lm_lists);

	nlmp = load_one(lml, nlmco, pnp, clmp, mode,
	    (flags | FLG_RT_HANDLE), &ghp);

	/*
	 * Remove any expanded pathname infrastructure, and if the dependency
	 * couldn't be loaded, cleanup.
	 */
	remove_pnode(pnp);
	if (nlmp == 0) {
		remove_cntl(lml, olmco);
		return (0);
	}

	/*
	 * If loading an auditor was requested, and the auditor already existed,
	 * then the link-map returned will be to the original auditor.  The new
	 * link-map list that was initially created, and the associated link-map
	 * control list are no longer needed.  As the auditor is already loaded,
	 * we're probably done, but fall through in case additional relocations
	 * would be triggered by the mode of the caller.
	 */
	if ((flags & FLG_RT_AUDIT) && (LIST(nlmp) != lml)) {
		remove_cntl(lml, olmco);
		lml = LIST(nlmp);
		olmco = 0;
		nlmco = ALIST_OFF_DATA;
	}

	/*
	 * Finish processing the objects associated with this request.
	 */
	if ((analyze_lmc(lml, nlmco, nlmp) == 0) ||
	    (relocate_lmc(lml, nlmco, clmp, nlmp) == 0)) {
		ghp = 0;
		nlmp = 0;
	}

	/*
	 * If this lazyload has failed, and we've created a new link-map
	 * control list to which this request has added objects, then remove
	 * all the objects that have been associated to this request.
	 */
	if ((nlmp == 0) && olmco && lmc->lc_head)
		remove_lmc(lml, clmp, lmc, olmco, path);

	/*
	 * Finally, remove any link-map control list that was created.
	 */
	if (olmco)
		remove_cntl(lml, olmco);

	return (ghp);
}

/*
 * Internal dlopen() activity.  Called from user level or directly for internal
 * opens that require a handle.
 */
Grp_hdl *
dlmopen_intn(Lm_list *lml, const char *path, int mode, Rt_map *clmp,
    uint_t flags, uint_t orig, int *loaded)
{
	Rt_map	*dlmp = 0;
	Grp_hdl	*ghp;
	int	objcnt;

	/*
	 * Check for magic link-map list values:
	 *
	 *  LM_ID_BASE:		Operate on the PRIMARY (executables) link map
	 *  LM_ID_LDSO:		Operation on ld.so.1's link map
	 *  LM_ID_NEWLM: 	Create a new link-map.
	 */
	if (lml == (Lm_list *)LM_ID_NEWLM) {
		if ((lml = calloc(sizeof (Lm_list), 1)) == 0)
			return (0);

		/*
		 * Establish the new link-map flags from the callers and those
		 * explicitly provided.
		 */
		lml->lm_tflags = LIST(clmp)->lm_tflags;
		if (flags & FLG_RT_AUDIT) {
			/*
			 * Unset any auditing flags - an auditor shouldn't be
			 * audited.  Insure all audit dependencies are loaded.
			 */
			lml->lm_tflags &= ~LML_TFLG_AUD_MASK;
			lml->lm_tflags |=
			    (LML_TFLG_NOLAZYLD | LML_TFLG_LOADFLTR);
			lml->lm_flags |= LML_FLG_NOAUDIT;
		}

		if (list_append(&dynlm_list, lml) == 0) {
			free(lml);
			return (0);
		}
		if (newlmid(lml) == 0) {
			list_delete(&dynlm_list, lml);
			free(lml);
			return (0);
		}
	} else if ((uintptr_t)lml < LM_ID_NUM) {
		if ((uintptr_t)lml == LM_ID_BASE)
			lml = &lml_main;
		else if ((uintptr_t)lml == LM_ID_LDSO)
			lml = &lml_rtld;
	}

	objcnt = lml->lm_obj;

	/*
	 * Open the required object on the associated link-map list.
	 */
	if ((ghp = dlmopen_core(lml, path, mode, clmp, flags,
	    (orig | PN_SER_DLOPEN))) != 0) {
		/*
		 * Establish the new link-map from which .init processing will
		 * begin.  Ignore .init firing when constructing a configuration
		 * file (crle(1)).
		 */
		if ((mode & RTLD_CONFGEN) == 0)
			dlmp = ghp->gh_ownlmp;
	}

	/*
	 * If loading an auditor was requested, and the auditor already existed,
	 * then the link-map returned will be to the original auditor.  Remove
	 * the link-map control list that was created for this request.
	 */
	if (dlmp && (flags & FLG_RT_AUDIT) && (LIST(dlmp) != lml)) {
		remove_lml(lml);
		lml = LIST(dlmp);
	}

	/*
	 * Return the number of objects loaded if required.  This is used to
	 * trigger used() processing on return from a dlopen().
	 */
	if (loaded)
		*loaded = lml->lm_obj - objcnt;

	/*
	 * If this load failed, remove any alternative link-map list.
	 */
	if ((ghp == 0) &&
	    ((lml->lm_flags & (LML_FLG_BASELM | LML_FLG_RTLDLM)) == 0)) {
		remove_lml(lml);
		lml = 0;
	}

	/*
	 * Finish this load request.  If objects were loaded, .init processing
	 * is computed.  Finally, the debuggers are informed of the link-map
	 * lists being stable.
	 */
	load_completion(dlmp);

	return (ghp);
}

/*
 * Argument checking for dlopen.  Only called via external entry.
 */
static Grp_hdl *
dlmopen_check(Lm_list *lml, const char *path, int mode, Rt_map *clmp,
    int *loaded)
{
	/*
	 * Verify that a valid pathname has been supplied.
	 */
	if (path && (*path == '\0')) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLPATH));
		return (0);
	}

	/*
	 * Historically we've always verified the mode is either RTLD_NOW or
	 * RTLD_LAZY.  RTLD_NOLOAD is valid by itself.  Use of LM_ID_NEWLM
	 * requires a specific pathname, and use of RTLD_PARENT is meaningless.
	 */
	if ((mode & (RTLD_NOW | RTLD_LAZY | RTLD_NOLOAD)) == 0) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_1));
		return (0);
	}
	if ((mode & (RTLD_NOW | RTLD_LAZY)) == (RTLD_NOW | RTLD_LAZY)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_2));
		return (0);
	}
	if ((lml == (Lm_list *)LM_ID_NEWLM) && (path == 0)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_3));
		return (0);
	}
	if ((lml == (Lm_list *)LM_ID_NEWLM) && (mode & RTLD_PARENT)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_4));
		return (0);
	}
	if (((mode & (RTLD_GROUP | RTLD_WORLD)) == 0) &&
	    ((mode & RTLD_NOLOAD) == 0))
		mode |= (RTLD_GROUP | RTLD_WORLD);
	if ((mode & RTLD_NOW) && (rtld_flags2 & RT_FL2_BINDLAZY)) {
		mode &= ~RTLD_NOW;
		mode |= RTLD_LAZY;
	}

	return (dlmopen_intn(lml, path, mode, clmp, 0, 0, loaded));
}

#pragma weak dlopen = _dlopen

/*
 * External entry for dlopen(3dl).  On success, returns a pointer (handle) to
 * the structure containing information about the newly added object, ie. can
 * be used by dlsym(). On failure, returns a null pointer.
 */
void *
_dlopen(const char *path, int mode)
{
	int	entry, loaded = 0;
	Rt_map	*clmp;
	Grp_hdl	*ghp;
	Lm_list	*lml;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);
	lml = LIST(clmp);

	ghp = dlmopen_check(lml, path, mode, clmp, &loaded);

	if (entry && ghp && loaded)
		unused(lml);

	if (entry)
		leave(lml);
	return ((void *)ghp);
}

/*
 * External entry for dlmopen(3dl).
 */
#pragma weak dlmopen = _dlmopen

void *
_dlmopen(Lmid_t lmid, const char *path, int mode)
{
	int	entry, loaded = 0;
	Rt_map	*clmp;
	Grp_hdl	*ghp;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);

	ghp = dlmopen_check((Lm_list *)lmid, path, mode, clmp, &loaded);

	if (entry && ghp && ghp->gh_ownlmp && loaded)
		unused(LIST(ghp->gh_ownlmp));

	if (entry)
		leave(LIST(clmp));
	return ((void *)ghp);
}

/*
 * Handle processing for dlsym.
 */
Sym *
dlsym_handle(Grp_hdl *ghp, Slookup *slp, Rt_map **_lmp, uint_t *binfo)
{
	Rt_map		*nlmp, * lmp = ghp->gh_ownlmp;
	Rt_map		*clmp = slp->sl_cmap;
	const char	*name = slp->sl_name;
	Sym		*sym = 0;
	Slookup		sl = *slp;

	sl.sl_flags = (LKUP_FIRST | LKUP_SPEC);

	/*
	 * Continue processing a dlsym request.  Lookup the required symbol in
	 * each link-map specified by the handle.
	 *
	 * To leverage off of lazy loading, dlsym() requests can result in two
	 * passes.  The first descends the link-maps of any objects already in
	 * the address space.  If the symbol isn't located, and lazy
	 * dependencies still exist, then a second pass is made to load these
	 * dependencies if applicable.  This model means that in the case where
	 * a symbols exists in more than one object, the one located may not be
	 * constant - this is the standard issue with lazy loading. In addition,
	 * attempting to locate a symbol that doesn't exist will result in the
	 * loading of all lazy dependencies on the given handle, which can
	 * defeat some of the advantages of lazy loading (look out JVM).
	 */
	if (ghp->gh_flags & GPH_ZERO) {
		Lm_list	*lml;

		/*
		 * If this symbol lookup is triggered from a dlopen(0) handle,
		 * traverse the present link-map list looking for promiscuous
		 * entries.
		 */
		for (nlmp = lmp; nlmp; nlmp = (Rt_map *)NEXT(nlmp)) {

			/*
			 * If this handle indicates we're only to look in the
			 * first object check whether we're done.
			 */
			if ((nlmp != lmp) && (ghp->gh_flags & GPH_FIRST))
				return ((Sym *)0);

			if (!(MODE(nlmp) & RTLD_GLOBAL))
				continue;
			if ((FLAGS(nlmp) & FLG_RT_DELETE) &&
			    ((FLAGS(clmp) & FLG_RT_DELETE) == 0))
				continue;

			sl.sl_imap = nlmp;
			if (sym = LM_LOOKUP_SYM(clmp)(&sl, _lmp, binfo))
				return (sym);
		}

		/*
		 * If we're unable to locate the symbol and this link-map still
		 * has pending lazy dependencies, start loading them in an
		 * attempt to exhaust the search.  Note that as we're already
		 * traversing a dynamic linked list of link-maps there's no
		 * need for elf_lazy_find_sym() to descend the link-maps itself.
		 */
		lml = LIST(lmp);
		if ((lml->lm_lazy) &&
		    ((lml->lm_flags & LML_FLG_NOPENDGLBLAZY) == 0)) {
			int	lazy = 0;

			DBG_CALL(Dbg_syms_lazy_rescan(lml, name));

			sl.sl_flags |= LKUP_NODESCENT;

			for (nlmp = lmp; nlmp; nlmp = (Rt_map *)NEXT(nlmp)) {

				if (!(MODE(nlmp) & RTLD_GLOBAL) || !LAZY(nlmp))
					continue;
				if ((FLAGS(nlmp) & FLG_RT_DELETE) &&
				    ((FLAGS(clmp) & FLG_RT_DELETE) == 0))
					continue;

				lazy = 1;
				sl.sl_imap = nlmp;
				if (sym = elf_lazy_find_sym(&sl, _lmp, binfo))
					return (sym);
			}

			/*
			 * If no global, lazy loadable dependencies are found,
			 * then none exist for this link-map list.  Pending lazy
			 * loadable objects may still exist for non-local
			 * objects that are associated with this link-map list,
			 * which is why we entered this fallback.  Tag this
			 * link-map list to prevent further searching for lazy
			 * dependencies.
			 */
			if (lazy == 0)
				lml->lm_flags |= LML_FLG_NOPENDGLBLAZY;
		}
	} else {
		/*
		 * Traverse the dlopen() handle for the presently loaded
		 * link-maps.
		 */
		Grp_desc	*gdp;
		Aliste		idx;

		for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
			if ((gdp->gd_flags & GPD_DLSYM) == 0)
				continue;

			sl.sl_imap = gdp->gd_depend;
			if (sym = LM_LOOKUP_SYM(clmp)(&sl, _lmp, binfo))
				return (sym);

			if (ghp->gh_flags & GPH_FIRST)
				return ((Sym *)0);
		}

		/*
		 * If we're unable to locate the symbol and this link-map still
		 * has pending lazy dependencies, start loading them in an
		 * attempt to exhaust the search.
		 */
		if ((LIST(lmp)->lm_lazy) &&
		    ((ghp->gh_flags & GPH_NOPENDLAZY) == 0)) {
			int	lazy = 0;

			DBG_CALL(Dbg_syms_lazy_rescan(LIST(lmp), name));

			for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
				nlmp = gdp->gd_depend;

				if (((gdp->gd_flags & GPD_DLSYM) == 0) ||
				    (LAZY(nlmp) == 0))
					continue;

				lazy = 1;
				sl.sl_imap = nlmp;
				if (sym = elf_lazy_find_sym(&sl, _lmp, binfo))
					return (sym);
			}

			/*
			 * If no lazy loadable dependencies are found, then
			 * none exist for this handle.  Pending lazy loadable
			 * objects may still exist for the associated link-map
			 * list, which is why we entered this fallback.  Tag
			 * this handle to prevent further searching for lazy
			 * dependencies.
			 */
			if (lazy == 0)
				ghp->gh_flags |= GPH_NOPENDLAZY;
		}
	}
	return ((Sym *)0);
}

/*
 * Core dlsym activity.  Selects symbol lookup method from handle.
 */
void *
dlsym_core(void *handle, const char *name, Rt_map *clmp, Rt_map **dlmp)
{
	Sym		*sym = NULL;
	Syminfo		*sip;
	Slookup		sl;
	uint_t		binfo;

	sl.sl_name = name;
	sl.sl_cmap = clmp;
	sl.sl_rsymndx = 0;
	sl.sl_rsym = 0;

	/*
	 * Standard relocations are evaluated using the symbol index of the
	 * associated relocation symbol.  This index provides for loading
	 * any lazy dependency and establishing a direct binding if necessary.
	 * If a dlsym() operation originates from an object that contains a
	 * symbol table entry for the same name, then establish the symbol
	 * index so that any dependency requirements can be triggered.
	 */
	sl.sl_imap = clmp;
	sl.sl_flags = LKUP_SYMNDX;
	sl.sl_hash = elf_hash(name);

	if ((FCT(clmp) == &elf_fct) &&
	    ((sym = SYMINTP(clmp)(&sl, 0, 0)) != NULL)) {
		sl.sl_rsymndx = (((ulong_t)sym -
		    (ulong_t)SYMTAB(clmp)) / SYMENT(clmp));
		sl.sl_rsym = sym;
	}

	if (sym && (ELF_ST_VISIBILITY(sym->st_other) == STV_SINGLETON)) {
		Rt_map	*hlmp = LIST(clmp)->lm_head;

		/*
		 * If a symbol reference is known, and that reference indicates
		 * that the symbol is a singleton, then the search for the
		 * symbol must follow the default search path.
		 */
		DBG_CALL(Dbg_syms_dlsym(clmp, name, 0, DBG_DLSYM_SINGLETON));

		sl.sl_imap = hlmp;
		sl.sl_flags = LKUP_SPEC;
		if (handle == RTLD_PROBE)
			sl.sl_flags |= LKUP_NOFALBACK;
		sym = LM_LOOKUP_SYM(clmp)(&sl, dlmp, &binfo);

	} else if (handle == RTLD_NEXT) {
		Rt_map	*nlmp;

		/*
		 * If this handle is RTLD_NEXT determine whether a lazy load
		 * from the caller might provide the next object.  This mimics
		 * the lazy loading initialization normally carried out by
		 * lookup_sym(), however here, we must do this up-front, as
		 * lookup_sym() will be used to inspect the next object.
		 */
		if ((sl.sl_rsymndx) && ((sip = SYMINFO(clmp)) != 0)) {
			/* LINTED */
			sip = (Syminfo *)((char *)sip +
			    (sl.sl_rsymndx * SYMINENT(clmp)));

			if ((sip->si_flags & SYMINFO_FLG_DIRECT) &&
			    (sip->si_boundto < SYMINFO_BT_LOWRESERVE))
				(void) elf_lazy_load(clmp,
				    sip->si_boundto, name);

			/*
			 * Clear the symbol index, so as not to confuse
			 * lookup_sym() of the next object.
			 */
			sl.sl_rsymndx = 0;
			sl.sl_rsym = 0;
		}

		/*
		 * If the handle is RTLD_NEXT start searching in the next link
		 * map from the callers.  Determine permissions from the
		 * present link map.  Indicate to lookup_sym() that we're on an
		 * RTLD_NEXT request so that it will use the callers link map to
		 * start any possible lazy dependency loading.
		 */
		sl.sl_imap = nlmp = (Rt_map *)NEXT(clmp);

		DBG_CALL(Dbg_syms_dlsym(clmp, name, (nlmp ? NAME(nlmp) :
		    MSG_INTL(MSG_STR_NULL)), DBG_DLSYM_NEXT));

		if (nlmp == 0)
			return (0);

		sl.sl_flags = LKUP_NEXT;
		sym = LM_LOOKUP_SYM(clmp)(&sl, dlmp, &binfo);

	} else if (handle == RTLD_SELF) {
		/*
		 * If the handle is RTLD_SELF start searching from the caller.
		 */
		DBG_CALL(Dbg_syms_dlsym(clmp, name, NAME(clmp),
		    DBG_DLSYM_SELF));

		sl.sl_imap = clmp;
		sl.sl_flags = (LKUP_SPEC | LKUP_SELF);
		sym = LM_LOOKUP_SYM(clmp)(&sl, dlmp, &binfo);

	} else if (handle == RTLD_DEFAULT) {
		Rt_map	*hlmp = LIST(clmp)->lm_head;

		/*
		 * If the handle is RTLD_DEFAULT mimic the standard symbol
		 * lookup as would be triggered by a relocation.
		 */
		DBG_CALL(Dbg_syms_dlsym(clmp, name, 0, DBG_DLSYM_DEFAULT));

		sl.sl_imap = hlmp;
		sl.sl_flags = LKUP_SPEC;
		sym = LM_LOOKUP_SYM(clmp)(&sl, dlmp, &binfo);

	} else if (handle == RTLD_PROBE) {
		Rt_map	*hlmp = LIST(clmp)->lm_head;

		/*
		 * If the handle is RTLD_PROBE, mimic the standard symbol
		 * lookup as would be triggered by a relocation, however do
		 * not fall back to a lazy loading rescan if the symbol can't be
		 * found within the currently loaded objects.  Note, a lazy
		 * loaded dependency required by the caller might still get
		 * loaded to satisfy this request, but no exhaustive lazy load
		 * rescan is carried out.
		 */
		DBG_CALL(Dbg_syms_dlsym(clmp, name, 0, DBG_DLSYM_PROBE));

		sl.sl_imap = hlmp;
		sl.sl_flags = (LKUP_SPEC | LKUP_NOFALBACK);
		sym = LM_LOOKUP_SYM(clmp)(&sl, dlmp, &binfo);

	} else {
		Grp_hdl *ghp = (Grp_hdl *)handle;

		/*
		 * Look in the shared object specified by the handle and in all
		 * of its dependencies.
		 */
		DBG_CALL(Dbg_syms_dlsym(clmp, name, NAME(ghp->gh_ownlmp),
		    DBG_DLSYM_DEF));

		sym = LM_DLSYM(clmp)(ghp, &sl, dlmp, &binfo);
	}

	if (sym) {
		Lm_list	*lml = LIST(clmp);
		Addr	addr = sym->st_value;

		if (!(FLAGS(*dlmp) & FLG_RT_FIXED))
			addr += ADDR(*dlmp);

		DBG_CALL(Dbg_bind_global(clmp, 0, 0, (Xword)-1, PLT_T_NONE,
		    *dlmp, addr, sym->st_value, name, binfo));

		if ((lml->lm_tflags | FLAGS1(clmp)) & LML_TFLG_AUD_SYMBIND) {
			uint_t	sb_flags = LA_SYMB_DLSYM;
			/* LINTED */
			uint_t	symndx = (uint_t)(((Xword)sym -
			    (Xword)SYMTAB(*dlmp)) / SYMENT(*dlmp));
			addr = audit_symbind(clmp, *dlmp, sym, symndx, addr,
			    &sb_flags);
		}
		return ((void *)addr);
	} else
		return (0);
}

/*
 * Internal dlsym activity.  Called from user level or directly for internal
 * symbol lookup.
 */
void *
dlsym_intn(void *handle, const char *name, Rt_map *clmp, Rt_map **dlmp)
{
	Rt_map		*llmp = 0;
	void		*error;
	Aliste		idx;
	Grp_desc	*gdp;

	/*
	 * While looking for symbols it's quite possible that additional objects
	 * get loaded from lazy loading.  These objects will have been added to
	 * the same link-map list as those objects on the handle.  Remember this
	 * list for later investigation.
	 */
	if ((handle == RTLD_NEXT) || (handle == RTLD_DEFAULT) ||
	    (handle == RTLD_SELF) || (handle == RTLD_PROBE))
		llmp = LIST(clmp)->lm_tail;
	else {
		Grp_hdl	*ghp = (Grp_hdl *)handle;

		if (ghp->gh_ownlmp)
			llmp = LIST(ghp->gh_ownlmp)->lm_tail;
		else {
			for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
				if ((llmp = LIST(gdp->gd_depend)->lm_tail) != 0)
					break;
			}
		}
	}

	if ((error = dlsym_core(handle, name, clmp, dlmp)) == 0) {
		/*
		 * Cache the error message, as Java tends to fall through this
		 * code many times.
		 */
		if (nosym_str == 0)
			nosym_str = MSG_INTL(MSG_GEN_NOSYM);
		eprintf(LIST(clmp), ERR_FATAL, nosym_str, name);
	}

	load_completion(llmp);
	return (error);
}

/*
 * Argument checking for dlsym.  Only called via external entry.
 */
static void *
dlsym_check(void *handle, const char *name, Rt_map *clmp, Rt_map **dlmp)
{
	/*
	 * Verify the arguments.
	 */
	if (name == 0) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_ILLSYM));
		return (0);
	}
	if ((handle != RTLD_NEXT) && (handle != RTLD_DEFAULT) &&
	    (handle != RTLD_SELF) && (handle != RTLD_PROBE) &&
	    (hdl_validate((Grp_hdl *)handle) == 0)) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_INVHNDL));
		return (0);
	}
	return (dlsym_intn(handle, name, clmp, dlmp));
}


#pragma weak dlsym = _dlsym

/*
 * External entry for dlsym().  On success, returns the address of the specified
 * symbol.  On error returns a null.
 */
void *
_dlsym(void *handle, const char *name)
{
	int	entry;
	Rt_map	*clmp, *dlmp = 0;
	void	*addr;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);

	addr = dlsym_check(handle, name, clmp, &dlmp);

	if (dlmp)
		is_dep_ready(dlmp, clmp, DBG_WAIT_SYMBOL);

	if (entry && dlmp)
		is_dep_init(dlmp, clmp);

	if (entry)
		leave(LIST(clmp));
	return (addr);
}

/*
 * Core dladdr activity.
 */
static void
dladdr_core(Rt_map *clmp, void *addr, Dl_info *dlip, void **info, int flags)
{
	/*
	 * Set up generic information and any defaults.
	 */
	dlip->dli_fname = PATHNAME(clmp);

	dlip->dli_fbase = (void *)ADDR(clmp);
	dlip->dli_sname = 0;
	dlip->dli_saddr = 0;

	/*
	 * Determine the nearest symbol to this address.
	 */
	LM_DLADDR(clmp)((ulong_t)addr, clmp, dlip, info, flags);
}

#pragma weak dladdr = _dladdr

/*
 * External entry for dladdr(3dl) and dladdr1(3dl).  Returns an information
 * structure that reflects the symbol closest to the address specified.
 */
int
_dladdr(void *addr, Dl_info *dlip)
{
	int	entry, error;
	Rt_map	*clmp;

	entry = enter();

	/*
	 * Use our calling technique to determine what object is associated
	 * with the supplied address.  If a caller can't be determined,
	 * indicate the failure.
	 */
	if ((clmp = _caller((caddr_t)addr, CL_NONE)) == 0) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_ARG_INVADDR),
		    EC_NATPTR(addr));
		error = 0;
	} else {
		dladdr_core(clmp, addr, dlip, 0, 0);
		error = 1;
	}

	if (entry)
		leave(0);
	return (error);
}

#pragma weak dladdr1 = _dladdr1

int
_dladdr1(void *addr, Dl_info *dlip, void **info, int flags)
{
	int	entry, error = 0;
	Rt_map	*clmp;

	/*
	 * Validate any flags.
	 */
	if (flags) {
		int	request;

		if (((request = (flags & RTLD_DL_MASK)) != RTLD_DL_SYMENT) &&
		    (request != RTLD_DL_LINKMAP)) {
			eprintf(0, ERR_FATAL, MSG_INTL(MSG_ARG_ILLFLAGS),
			    flags);
			return (0);
		}
		if (info == 0) {
			eprintf(0, ERR_FATAL, MSG_INTL(MSG_ARG_ILLINFO), flags);
			return (0);
		}
	}

	entry = enter();

	/*
	 * Use our calling technique to determine what object is associated
	 * with the supplied address.  If a caller can't be determined,
	 * indicate the failure.
	 */
	if ((clmp = _caller((caddr_t)addr, CL_NONE)) == 0) {
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_ARG_INVADDR),
		    EC_NATPTR(addr));
		error = 0;
	} else {
		dladdr_core(clmp, addr, dlip, info, flags);
		error = 1;
	}

	if (entry)
		leave(0);
	return (error);
}

/*
 * Core dldump activity.
 */
static int
dldump_core(Lm_list *lml, const char *ipath, const char *opath, int flags)
{
	Addr	addr = 0;
	Rt_map	*lmp;

	/*
	 * Verify any arguments first.
	 */
	if ((!opath || (*opath == '\0')) || (ipath && (*ipath == '\0'))) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLPATH));
		return (1);
	}

	/*
	 * If an input file is specified make sure its one of our dependencies
	 * on the main link-map list.  Note, this has really all evolved for
	 * crle(), which uses libcrle.so on an alternative link-map to trigger
	 * dumping objects from the main link-map list.   If we ever want to
	 * dump objects from alternative link-maps, this model is going to
	 * have to be revisited.
	 */
	if (ipath) {
		if ((lmp = is_so_loaded(&lml_main, ipath)) == 0) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_NOFILE),
			    ipath);
			return (1);
		}
		if (FLAGS(lmp) & FLG_RT_ALTER) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_ALTER), ipath);
			return (1);
		}
		if (FLAGS(lmp) & FLG_RT_NODUMP) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_NODUMP),
			    ipath);
			return (1);
		}
	} else
		lmp = lml_main.lm_head;


	DBG_CALL(Dbg_file_dldump(lmp, opath, flags));

	/*
	 * If the object being dump'ed isn't fixed identify its mapping.
	 */
	if (!(FLAGS(lmp) & FLG_RT_FIXED))
		addr = ADDR(lmp);

	/*
	 * As rt_dldump() will effectively lazy load the necessary support
	 * libraries, make sure ld.so.1 is initialized for plt relocations.
	 */
	if (elf_rtld_load() == 0)
		return (0);

	/*
	 * Dump the required image.
	 */
	return (rt_dldump(lmp, opath, flags, addr));
}

#pragma weak dldump = _dldump

/*
 * External entry for dldump(3c).  Returns 0 on success, non-zero otherwise.
 */
int
_dldump(const char *ipath, const char *opath, int flags)
{
	int	error, entry;
	Rt_map	*clmp;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);

	error = dldump_core(LIST(clmp), ipath, opath, flags);

	if (entry)
		leave(LIST(clmp));
	return (error);
}

/*
 * get_linkmap_id() translates Lm_list * pointers to the Link_map id as used by
 * the rtld_db and dlmopen() interfaces.  It checks to see if the Link_map is
 * one of the primary ones and if so returns it's special token:
 *		LM_ID_BASE
 *		LM_ID_LDSO
 *
 * If it's not one of the primary link_map id's it will instead returns a
 * pointer to the Lm_list structure which uniquely identifies the Link_map.
 */
Lmid_t
get_linkmap_id(Lm_list *lml)
{
	if (lml->lm_flags & LML_FLG_BASELM)
		return (LM_ID_BASE);
	if (lml->lm_flags & LML_FLG_RTLDLM)
		return (LM_ID_LDSO);

	return ((Lmid_t)lml);
}

/*
 * Extract information for a dlopen() handle.
 */
static int
dlinfo_core(void *handle, int request, void *p, Rt_map *clmp)
{
	Lm_list	*lml = LIST(clmp);
	Rt_map	*lmp;

	if ((request > RTLD_DI_MAX) || (p == 0)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLVAL));
		return (-1);
	}

	/*
	 * Return configuration cache name and address.
	 */
	if (request == RTLD_DI_CONFIGADDR) {
		Dl_info	*dlip = (Dl_info *)p;

		if ((config->c_name == 0) || (config->c_bgn == 0) ||
		    (config->c_end == 0)) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_NOCONFIG));
			return (-1);
		}
		dlip->dli_fname = config->c_name;
		dlip->dli_fbase = (void *)config->c_bgn;
		return (0);
	}

	/*
	 * Return profiled object name (used by ldprof audit library).
	 */
	if (request == RTLD_DI_PROFILENAME) {
		if (profile_name == 0) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_NOPROFNAME));
			return (-1);
		}

		*(const char **)p = profile_name;
		return (0);
	}
	if (request == RTLD_DI_PROFILEOUT) {
		/*
		 * If a profile destination directory hasn't been specified
		 * provide a default.
		 */
		if (profile_out == 0)
			profile_out = MSG_ORIG(MSG_PTH_VARTMP);

		*(const char **)p = profile_out;
		return (0);
	}

	/*
	 * Obtain or establish a termination signal.
	 */
	if (request == RTLD_DI_GETSIGNAL) {
		*(int *)p = killsig;
		return (0);
	}

	if (request == RTLD_DI_SETSIGNAL) {
		sigset_t	set;
		int		sig = *(int *)p;

		/*
		 * Determine whether the signal is in range.
		 */
		(void) sigfillset(&set);
		if (sigismember(&set, sig) != 1) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_INVSIG), sig);
			return (-1);
		}

		killsig = sig;
		return (0);
	}

	/*
	 * For any other request a link-map is required.  Verify the handle.
	 */
	if (handle == RTLD_SELF)
		lmp = clmp;
	else {
		Grp_hdl	*ghp = (Grp_hdl *)handle;

		if (!hdl_validate(ghp)) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_INVHNDL));
			return (-1);
		}
		lmp = ghp->gh_ownlmp;
	}

	/*
	 * Obtain the process arguments, environment and auxv.  Note, as the
	 * environment can be modified by the user (putenv(3c)), reinitialize
	 * the environment pointer on each request.
	 */
	if (request == RTLD_DI_ARGSINFO) {
		Dl_argsinfo	*aip = (Dl_argsinfo *)p;
		Lm_list		*lml = LIST(lmp);

		*aip = argsinfo;
		if (lml->lm_flags & LML_FLG_ENVIRON)
			aip->dla_envp = *(lml->lm_environ);

		return (0);
	}

	/*
	 * Return Lmid_t of the Link-Map list that the specified object is
	 * loaded on.
	 */
	if (request == RTLD_DI_LMID) {
		*(Lmid_t *)p = get_linkmap_id(LIST(lmp));
		return (0);
	}

	/*
	 * Return a pointer to the Link-Map structure associated with the
	 * specified object.
	 */
	if (request == RTLD_DI_LINKMAP) {
		*(Link_map **)p = (Link_map *)lmp;
		return (0);
	}

	/*
	 * Return search path information, or the size of the buffer required
	 * to store the information.
	 */
	if ((request == RTLD_DI_SERINFO) || (request == RTLD_DI_SERINFOSIZE)) {
		Pnode		*dir, *dirlist = (Pnode *)0;
		Dl_serinfo	*info;
		Dl_serpath	*path;
		char		*strs;
		size_t		size = sizeof (Dl_serinfo);
		uint_t		cnt = 0;

		info = (Dl_serinfo *)p;
		path = &info->dls_serpath[0];
		strs = (char *)&info->dls_serpath[info->dls_cnt];

		/*
		 * Traverse search path entries for this object.
		 */
		while ((dir = get_next_dir(&dirlist, lmp, 0)) != 0) {
			size_t	_size;

			if (dir->p_name == 0)
				continue;

			/*
			 * If configuration information exists, it's possible
			 * this path has been identified as non-existent, if so
			 * ignore it.
			 */
			if (dir->p_info) {
				Rtc_obj	*dobj = (Rtc_obj *)dir->p_info;
				if (dobj->co_flags & RTC_OBJ_NOEXIST)
					continue;
			}

			/*
			 * Keep track of search path count and total info size.
			 */
			if (cnt++)
				size += sizeof (Dl_serpath);
			_size = strlen(dir->p_name) + 1;
			size += _size;

			if (request == RTLD_DI_SERINFOSIZE)
				continue;

			/*
			 * If we're filling in search path information, confirm
			 * there's sufficient space.
			 */
			if (size > info->dls_size) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_ARG_SERSIZE),
				    EC_OFF(info->dls_size));
				return (-1);
			}
			if (cnt > info->dls_cnt) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_ARG_SERCNT), info->dls_cnt);
				return (-1);
			}

			/*
			 * Append the path to the information buffer.
			 */
			(void) strcpy(strs, dir->p_name);
			path->dls_name = strs;
			path->dls_flags = dir->p_orig;

			strs = strs + _size;
			path++;
		}

		/*
		 * If we're here to size the search buffer fill it in.
		 */
		if (request == RTLD_DI_SERINFOSIZE) {
			info->dls_size = size;
			info->dls_cnt = cnt;
		}
	}

	/*
	 * Return the origin of the object associated with this link-map.
	 * Basically return the dirname(1) of the objects fullpath.
	 */
	if (request == RTLD_DI_ORIGIN) {
		char	*str = (char *)p;

		if (DIRSZ(lmp) == 0)
			(void) fullpath(lmp, 0);

		(void) strncpy(str, ORIGNAME(lmp), DIRSZ(lmp));
		str += DIRSZ(lmp);
		*str = '\0';

		return (0);
	}

	return (0);
}

#pragma weak dlinfo = _dlinfo

/*
 * External entry for dlinfo(3dl).
 */
int
_dlinfo(void *handle, int request, void *p)
{
	int	error, entry;
	Rt_map	*clmp;

	entry = enter();

	clmp = _caller(caller(), CL_EXECDEF);

	error = dlinfo_core(handle, request, p, clmp);

	if (entry)
		leave(LIST(clmp));
	return (error);
}
