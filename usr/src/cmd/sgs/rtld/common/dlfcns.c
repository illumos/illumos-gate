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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * Programmatic interface to the run_time linker.
 */

#include	<sys/debug.h>
#include	<stdio.h>
#include	<string.h>
#include	<dlfcn.h>
#include	<synch.h>
#include	<limits.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"_inline_gen.h"
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
	Lm_list	*lml;
	Aliste	idx1;

	for (APLIST_TRAVERSE(dynlm_list, idx1, lml)) {
		Aliste	idx2;
		Lm_cntl	*lmc;

		for (ALIST_TRAVERSE(lml->lm_lists, idx2, lmc)) {
			Rt_map	*lmp;

			for (lmp = lmc->lc_head; lmp;
			    lmp = NEXT_RT_MAP(lmp)) {

				if (find_segment(cpc, lmp))
					return (lmp);
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

#pragma weak _dlerror = dlerror

/*
 * External entry for dlerror(3dl).  Returns a pointer to the string describing
 * the last occurring error.  The last occurring error is cleared.
 */
char *
dlerror()
{
	char	*error;
	Rt_map	*clmp;
	int	entry;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);

	DBG_CALL(Dbg_dl_dlerror(clmp, lasterr));

	error = lasterr;
	lasterr = NULL;

	if (entry)
		leave(LIST(clmp), 0);
	return (error);
}

/*
 * Add a dependency as a group descriptor to a group handle.  Returns 0 on
 * failure.  On success, returns the group descriptor, and if alep is non-NULL
 * the *alep is set to ALE_EXISTS if the dependency already exists, or to
 * ALE_CREATE if the dependency is newly created.
 */
Grp_desc *
hdl_add(Grp_hdl *ghp, Rt_map *lmp, uint_t dflags, int *alep)
{
	Grp_desc	*gdp;
	Aliste		idx;
	int		ale = ALE_CREATE;
	uint_t		oflags;

	/*
	 * Make sure this dependency hasn't already been recorded.
	 */
	for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
		if (gdp->gd_depend == lmp) {
			ale = ALE_EXISTS;
			break;
		}
	}

	if (ale == ALE_CREATE) {
		Grp_desc	gd;

		/*
		 * Create a new handle descriptor.
		 */
		gd.gd_depend = lmp;
		gd.gd_flags = 0;

		/*
		 * Indicate this object is a part of this handles group.
		 */
		if (aplist_append(&GROUPS(lmp), ghp, AL_CNT_GROUPS) == NULL)
			return (NULL);

		/*
		 * Append the new dependency to this handle.
		 */
		if ((gdp = alist_append(&ghp->gh_depends, &gd,
		    sizeof (Grp_desc), AL_CNT_DEPENDS)) == NULL)
			return (NULL);
	}

	oflags = gdp->gd_flags;
	gdp->gd_flags |= dflags;

	if (DBG_ENABLED) {
		if (ale == ALE_CREATE)
			DBG_CALL(Dbg_file_hdl_action(ghp, lmp, DBG_DEP_ADD,
			    gdp->gd_flags));
		else if (gdp->gd_flags != oflags)
			DBG_CALL(Dbg_file_hdl_action(ghp, lmp, DBG_DEP_UPDATE,
			    gdp->gd_flags));
	}

	if (alep)
		*alep = ale;
	return (gdp);
}

/*
 * Create a handle.
 *
 *   rlmp -	represents the reference link-map for which the handle is being
 *		created.
 *   clmp -	represents the caller who is requesting the handle.
 *   hflags -	provide group handle flags (GPH_*) that affect the use of the
 *		handle, such as dlopen(0), or use or use of RTLD_FIRST.
 *   rdflags -	provide group dependency flags for the reference link-map rlmp,
 *		such as whether the dependency can be used for dlsym(), can be
 *		relocated against, or whether this objects dependencies should
 *		be processed.
 *   cdflags -	provide group dependency flags for the caller.
 */
Grp_hdl *
hdl_create(Lm_list *lml, Rt_map *rlmp, Rt_map *clmp, uint_t hflags,
    uint_t rdflags, uint_t cdflags)
{
	Grp_hdl	*ghp = NULL, *aghp;
	APlist	**alpp;
	Aliste	idx;

	/*
	 * For dlopen(0) the handle is maintained as part of the link-map list,
	 * otherwise the handle is associated with the reference link-map.
	 */
	if (hflags & GPH_ZERO)
		alpp = &(lml->lm_handle);
	else
		alpp = &(HANDLES(rlmp));

	/*
	 * Objects can contain multiple handles depending on the handle flags
	 * supplied.  Most RTLD flags pertain to the object itself and the
	 * bindings that it can achieve.  Multiple handles for these flags
	 * don't make sense.  But if the flag determines how the handle might
	 * be used, then multiple handles may exist.  Presently this only makes
	 * sense for RTLD_FIRST.  Determine if an appropriate handle already
	 * exists.
	 */
	for (APLIST_TRAVERSE(*alpp, idx, aghp)) {
		if ((aghp->gh_flags & GPH_FIRST) == (hflags & GPH_FIRST)) {
			ghp = aghp;
			break;
		}
	}

	if (ghp == NULL) {
		uint_t	ndx;

		/*
		 * If this is the first request for this handle, allocate and
		 * initialize a new handle.
		 */
		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_CREATE));

		if ((ghp = malloc(sizeof (Grp_hdl))) == NULL)
			return (NULL);

		/*
		 * Associate the handle with the link-map list or the reference
		 * link-map as appropriate.
		 */
		if (aplist_append(alpp, ghp, AL_CNT_GROUPS) == NULL) {
			free(ghp);
			return (NULL);
		}

		/*
		 * Record the existence of this handle for future verification.
		 */
		/* LINTED */
		ndx = (uintptr_t)ghp % HDLIST_SZ;

		if (aplist_append(&hdl_alp[ndx], ghp, AL_CNT_HANDLES) == NULL) {
			(void) aplist_delete_value(*alpp, ghp);
			free(ghp);
			return (NULL);
		}

		ghp->gh_depends = NULL;
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
			ghp->gh_ownlmp = rlmp;
			ghp->gh_ownlml = LIST(rlmp);

			if (hdl_add(ghp, rlmp, rdflags, NULL) == NULL)
				return (NULL);

			/*
			 * If this new handle is a private handle, there's no
			 * need to track the caller, so we're done.
			 */
			if (hflags & GPH_PRIVATE)
				return (ghp);

			/*
			 * If this new handle is public, and isn't a special
			 * handle representing ld.so.1, indicate that a local
			 * group now exists.  This state allows singleton
			 * searches to be optimized.
			 */
			if ((hflags & GPH_LDSO) == 0)
				LIST(rlmp)->lm_flags |= LML_FLG_GROUPSEXIST;
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

			(void) aplist_delete_value(hdl_alp[HDLIST_ORP], ghp);
			(void) aplist_append(&hdl_alp[ndx], ghp,
			    AL_CNT_HANDLES);

			if (DBG_ENABLED) {
				Aliste		idx;
				Grp_desc	*gdp;

				DBG_CALL(Dbg_file_hdl_title(DBG_HDL_REINST));
				for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp))
					DBG_CALL(Dbg_file_hdl_action(ghp,
					    gdp->gd_depend, DBG_DEP_REINST, 0));
			}
		}

		/*
		 * If we've been asked to create a private handle, there's no
		 * need to track the caller.
		 */
		if (hflags & GPH_PRIVATE) {
			/*
			 * Negate the reference count increment.
			 */
			ghp->gh_refcnt--;
			return (ghp);
		} else {
			/*
			 * If a private handle already exists, promote this
			 * handle to public by initializing both the reference
			 * count and the handle flags.
			 */
			if (ghp->gh_flags & GPH_PRIVATE) {
				ghp->gh_refcnt = 1;
				ghp->gh_flags &= ~GPH_PRIVATE;
				ghp->gh_flags |= hflags;
			}
		}
	}

	/*
	 * Keep track of the parent (caller).  As this object can be referenced
	 * by different parents, this processing is carried out every time a
	 * handle is requested.
	 */
	if (clmp && (hdl_add(ghp, clmp, cdflags, NULL) == NULL))
		return (NULL);

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
		Rt_map		*lmp = gdp->gd_depend;
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
			Rt_map	*dlmp = bdp->b_depend;

			if ((bdp->b_flags & BND_NEEDED) == 0)
				continue;

			if (hdl_add(ghp, dlmp,
			    (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS), NULL) == NULL)
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
	Aliste		idx;
	Grp_hdl		*lghp;
	uint_t		ndx;

	/* LINTED */
	ndx = (uintptr_t)ghp % HDLIST_SZ;

	for (APLIST_TRAVERSE(hdl_alp[ndx], idx, lghp)) {
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
	Rt_map	*lmp;

	/*
	 * If we're already at atexit() there's no point processing further,
	 * all objects have already been tsorted for fini processing.
	 */
	if (rtld_flags & RT_FL_ATEXIT)
		return (0);

	/*
	 * Diagnose what we're up to.
	 */
	if (ghp->gh_flags & GPH_ZERO) {
		DBG_CALL(Dbg_dl_dlclose(clmp, MSG_ORIG(MSG_STR_ZERO),
		    DBG_DLCLOSE_IGNORE));
	} else {
		DBG_CALL(Dbg_dl_dlclose(clmp, NAME(ghp->gh_ownlmp),
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
	 * If this handle is associated with an object that is not on the base
	 * link-map control list, or it has not yet been relocated, then this
	 * handle must have originated from an auditors interaction, or some
	 * permutation of RTLD_CONFGEN use (crle(1), moe(1), etc.).  User code
	 * can only execute and bind to relocated objects on the base link-map
	 * control list.  Outside of RTLD_CONFGEN use, a non-relocated object,
	 * or an object on a non-base link-map control list, is in the process
	 * of being loaded, and therefore we do not attempt to remove the
	 * handle.
	 */
	if (((lmp = ghp->gh_ownlmp) != NULL) &&
	    ((MODE(lmp) & RTLD_CONFGEN) == 0) &&
	    ((CNTL(lmp) != ALIST_OFF_DATA) ||
	    ((FLAGS(lmp) & FLG_RT_RELOCED) == 0)))
		return (0);

	/*
	 * This handle is no longer being referenced, remove it.  If this handle
	 * is part of an alternative link-map list, determine if the whole list
	 * can be removed also.
	 */
	error = remove_hdl(ghp, clmp, NULL);

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
	Rt_map	*nlmp = NULL;
	Lm_list	*olml = NULL;
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
		Aliste	idx;
		Lm_list	*lml;

		for (APLIST_TRAVERSE(dynlm_list, idx, lml)) {
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
		Conv_inv_buf_t	inv_buf;

		(void) conv_invalid_val(&inv_buf, EC_NATPTR(ghp), 0);
		DBG_CALL(Dbg_dl_dlclose(clmp, inv_buf.buf, DBG_DLCLOSE_NULL));

		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_INVHNDL),
		    EC_NATPTR(handle));
		return (1);
	}
	return (dlclose_intn(ghp, clmp));
}

#pragma weak _dlclose = dlclose

/*
 * External entry for dlclose(3dl).  Returns 0 for success, non-zero otherwise.
 */
int
dlclose(void *handle)
{
	int		error, entry;
	Rt_map		*clmp;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);

	error = dlclose_check(handle, clmp);

	if (entry)
		leave(LIST(clmp), 0);
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
	if ((lml->lm_lmidstr = strdup(buffer)) == NULL)
		return (0);

	return (1);
}

/*
 * Core dlopen activity.
 */
static Grp_hdl *
dlmopen_core(Lm_list *lml, Lm_list *olml, const char *path, int mode,
    Rt_map *clmp, uint_t flags, uint_t orig, int *in_nfavl)
{
	Alist		*palp = NULL;
	Rt_map		*nlmp;
	Grp_hdl		*ghp;
	Aliste		olmco, nlmco;

	DBG_CALL(Dbg_dl_dlopen(clmp,
	    (path ? path : MSG_ORIG(MSG_STR_ZERO)), in_nfavl, mode));

	/*
	 * Having diagnosed the originally defined modes, assign any defaults
	 * or corrections.
	 */
	if (((mode & (RTLD_GROUP | RTLD_WORLD)) == 0) &&
	    ((mode & RTLD_NOLOAD) == 0))
		mode |= (RTLD_GROUP | RTLD_WORLD);
	if ((mode & RTLD_NOW) && (rtld_flags2 & RT_FL2_BINDLAZY)) {
		mode &= ~RTLD_NOW;
		mode |= RTLD_LAZY;
	}

	/*
	 * If the path specified is null then we're operating on global
	 * objects.  Associate a dummy handle with the link-map list.
	 */
	if (path == NULL) {
		Grp_hdl *ghp;
		uint_t	hflags, rdflags, cdflags;
		int	promote = 0;

		/*
		 * Establish any flags for the handle (Grp_hdl).
		 *
		 *  -	This is a dummy, public, handle (0) that provides for a
		 *	dynamic	search of all global objects within the process.
		 *  -   Use of the RTLD_FIRST mode indicates that only the first
		 *	dependency on the handle (the referenced object) can be
		 *	used to satisfy dlsym() requests.
		 */
		hflags = (GPH_PUBLIC | GPH_ZERO);
		if (mode & RTLD_FIRST)
			hflags |= GPH_FIRST;

		/*
		 * Establish the flags for the referenced dependency descriptor
		 * (Grp_desc).
		 *
		 *  -	The referenced object is available for dlsym().
		 *  -	The referenced object is available to relocate against.
		 *  -	The referenced object should have it's dependencies
		 *	added to this handle.
		 */
		rdflags = (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS);

		/*
		 * Establish the flags for this callers dependency descriptor
		 * (Grp_desc).
		 *
		 *  -	The explicit creation of a handle creates a descriptor
		 *	for the referenced object and the parent (caller).
		 *  -	Use of the RTLD_PARENT flag indicates that the parent
		 *	can be relocated against.
		 */
		cdflags = GPD_PARENT;
		if (mode & RTLD_PARENT)
			cdflags |= GPD_RELOC;

		if ((ghp = hdl_create(lml, 0, clmp, hflags, rdflags,
		    cdflags)) == NULL)
			return (NULL);

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

		for (nlmp = lml->lm_head; nlmp; nlmp = NEXT_RT_MAP(nlmp)) {
			if (((MODE(nlmp) & RTLD_GLOBAL) == 0) ||
			    (FLAGS(nlmp) & FLG_RT_DELETE))
				continue;

			if (update_mode(nlmp, MODE(nlmp), mode))
				promote = 1;
		}
		if (promote)
			(void) relocate_lmc(lml, ALIST_OFF_DATA, clmp,
			    lml->lm_head, in_nfavl);

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
	if (LM_FIX_NAME(clmp)(path, clmp, &palp, AL_CNT_NEEDED, orig) == NULL)
		return (NULL);

	if ((palp->al_arritems > 1) && ((mode & RTLD_FIRST) == 0)) {
		remove_alist(&palp, 1);
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_5));
		return (NULL);
	}

	/*
	 * Establish a link-map control list for this request, and load the
	 * associated object.
	 */
	if ((nlmco = create_cntl(lml, 1)) == NULL) {
		remove_alist(&palp, 1);
		return (NULL);
	}
	olmco = nlmco;

	nlmp = load_one(lml, nlmco, palp, clmp, mode, (flags | FLG_RT_PUBHDL),
	    &ghp, in_nfavl);

	/*
	 * Remove any expanded pathname infrastructure, and if the dependency
	 * couldn't be loaded, cleanup.
	 */
	remove_alist(&palp, 1);
	if (nlmp == NULL) {
		remove_cntl(lml, olmco);
		return (NULL);
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
	if (((nlmp = analyze_lmc(lml, nlmco, nlmp, clmp, in_nfavl)) == NULL) ||
	    (relocate_lmc(lml, nlmco, clmp, nlmp, in_nfavl) == 0)) {
		ghp = NULL;
		nlmp = NULL;
	}

	/*
	 * If the dlopen has failed, clean up any objects that might have been
	 * loaded successfully on this new link-map control list.
	 */
	if (olmco && (nlmp == NULL))
		remove_lmc(lml, clmp, olmco, path);

	/*
	 * Finally, remove any temporary link-map control list.  Note, if this
	 * operation successfully established a new link-map list, then a base
	 * link-map control list will have been created, which must remain.
	 */
	if (olmco && ((nlmp == NULL) || (olml != (Lm_list *)LM_ID_NEWLM)))
		remove_cntl(lml, olmco);

	return (ghp);
}

/*
 * dlopen() and dlsym() operations are the means by which a process can
 * test for the existence of required dependencies.  If the necessary
 * dependencies don't exist, then associated functionality can't be used.
 * However, the lack of dependencies can be fixed, and the dlopen() and
 * dlsym() requests can be repeated.  As we use a "not-found" AVL tree to
 * cache any failed full path loads, secondary dlopen() and dlsym() requests
 * will fail, even if the dependencies have been installed.
 *
 * dlopen() and dlsym() retry any failures by removing the "not-found" AVL
 * tree.  Should any dependencies be found, their names are added to the
 * FullPath AVL tree.  This routine removes any new "not-found" AVL tree,
 * so that the dlopen() or dlsym() can replace the original "not-found" tree.
 */
inline static void
nfavl_remove(avl_tree_t *avlt)
{
	PathNode	*pnp;
	void		*cookie = NULL;

	if (avlt) {
		while ((pnp = avl_destroy_nodes(avlt, &cookie)) != NULL)
			free(pnp);

		avl_destroy(avlt);
		free(avlt);
	}
}

/*
 * Internal dlopen() activity.  Called from user level or directly for internal
 * opens that require a handle.
 */
Grp_hdl *
dlmopen_intn(Lm_list *lml, const char *path, int mode, Rt_map *clmp,
    uint_t flags, uint_t orig)
{
	Lm_list	*olml = lml;
	Rt_map	*dlmp = NULL;
	Grp_hdl	*ghp;
	int	in_nfavl = 0;

	/*
	 * Check for magic link-map list values:
	 *
	 *  LM_ID_BASE:		Operate on the PRIMARY (executables) link map
	 *  LM_ID_LDSO:		Operation on ld.so.1's link map
	 *  LM_ID_NEWLM: 	Create a new link-map.
	 */
	if (lml == (Lm_list *)LM_ID_NEWLM) {
		if ((lml = calloc(sizeof (Lm_list), 1)) == NULL)
			return (NULL);

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
			lml->lm_tflags |= (LML_TFLG_NOLAZYLD |
			    LML_TFLG_LOADFLTR | LML_TFLG_NOAUDIT);
		}

		if (aplist_append(&dynlm_list, lml, AL_CNT_DYNLIST) == NULL) {
			free(lml);
			return (NULL);
		}
		if (newlmid(lml) == 0) {
			(void) aplist_delete_value(dynlm_list, lml);
			free(lml);
			return (NULL);
		}
	} else if ((uintptr_t)lml < LM_ID_NUM) {
		if ((uintptr_t)lml == LM_ID_BASE)
			lml = &lml_main;
		else if ((uintptr_t)lml == LM_ID_LDSO)
			lml = &lml_rtld;
	}

	/*
	 * Open the required object on the associated link-map list.
	 */
	ghp = dlmopen_core(lml, olml, path, mode, clmp, flags, orig, &in_nfavl);

	/*
	 * If the object could not be found it is possible that the "not-found"
	 * AVL tree had indicated that the file does not exist.  In case the
	 * file system has changed since this "not-found" recording was made,
	 * retry the dlopen() with a clean "not-found" AVL tree.
	 */
	if ((ghp == NULL) && in_nfavl) {
		avl_tree_t	*oavlt = nfavl;

		nfavl = NULL;
		ghp = dlmopen_core(lml, olml, path, mode, clmp, flags, orig,
		    NULL);

		/*
		 * If the file is found, then its full path name will have been
		 * registered in the FullPath AVL tree.  Remove any new
		 * "not-found" AVL information, and restore the former AVL tree.
		 */
		nfavl_remove(nfavl);
		nfavl = oavlt;
	}

	/*
	 * Establish the new link-map from which .init processing will begin.
	 * Ignore .init firing when constructing a configuration file (crle(1)).
	 */
	if (ghp && ((mode & RTLD_CONFGEN) == 0))
		dlmp = ghp->gh_ownlmp;

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
	 * If this load failed, remove any alternative link-map list.
	 */
	if ((ghp == NULL) &&
	    ((lml->lm_flags & (LML_FLG_BASELM | LML_FLG_RTLDLM)) == 0)) {
		remove_lml(lml);
		lml = NULL;
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
dlmopen_check(Lm_list *lml, const char *path, int mode, Rt_map *clmp)
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
	if ((lml == (Lm_list *)LM_ID_NEWLM) && (path == NULL)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_3));
		return (0);
	}
	if ((lml == (Lm_list *)LM_ID_NEWLM) && (mode & RTLD_PARENT)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLMODE_4));
		return (0);
	}

	return (dlmopen_intn(lml, path, mode, clmp, 0, 0));
}

#pragma weak _dlopen = dlopen

/*
 * External entry for dlopen(3dl).  On success, returns a pointer (handle) to
 * the structure containing information about the newly added object, ie. can
 * be used by dlsym(). On failure, returns a null pointer.
 */
void *
dlopen(const char *path, int mode)
{
	int	entry;
	Rt_map	*clmp;
	Grp_hdl	*ghp;
	Lm_list	*lml;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);
	lml = LIST(clmp);

	ghp = dlmopen_check(lml, path, mode, clmp);

	if (entry)
		leave(lml, 0);
	return ((void *)ghp);
}

#pragma weak _dlmopen = dlmopen

/*
 * External entry for dlmopen(3dl).
 */
void *
dlmopen(Lmid_t lmid, const char *path, int mode)
{
	int	entry;
	Rt_map	*clmp;
	Grp_hdl	*ghp;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);

	ghp = dlmopen_check((Lm_list *)lmid, path, mode, clmp);

	if (entry)
		leave(LIST(clmp), 0);
	return ((void *)ghp);
}

/*
 * Handle processing for dlsym.
 */
int
dlsym_handle(Grp_hdl *ghp, Slookup *slp, Sresult *srp, uint_t *binfo,
    int *in_nfavl)
{
	Rt_map		*nlmp, * lmp = ghp->gh_ownlmp;
	Rt_map		*clmp = slp->sl_cmap;
	const char	*name = slp->sl_name;
	Slookup		sl = *slp;

	sl.sl_flags = (LKUP_FIRST | LKUP_DLSYM | LKUP_SPEC);

	/*
	 * Continue processing a dlsym request.  Lookup the required symbol in
	 * each link-map specified by the handle.
	 *
	 * To leverage off of lazy loading, dlsym() requests can result in two
	 * passes.  The first descends the link-maps of any objects already in
	 * the address space.  If the symbol isn't located, and lazy
	 * dependencies still exist, then a second pass is made to load these
	 * dependencies if applicable.  This model means that in the case where
	 * a symbol exists in more than one object, the one located may not be
	 * constant - this is the standard issue with lazy loading. In addition,
	 * attempting to locate a symbol that doesn't exist will result in the
	 * loading of all lazy dependencies on the given handle, which can
	 * defeat some of the advantages of lazy loading (look out JVM).
	 */
	if (ghp->gh_flags & GPH_ZERO) {
		Lm_list	*lml;
		uint_t	lazy = 0;

		/*
		 * If this symbol lookup is triggered from a dlopen(0) handle,
		 * traverse the present link-map list looking for promiscuous
		 * entries.
		 */
		for (nlmp = lmp; nlmp; nlmp = NEXT_RT_MAP(nlmp)) {
			/*
			 * If this handle indicates we're only to look in the
			 * first object check whether we're done.
			 */
			if ((nlmp != lmp) && (ghp->gh_flags & GPH_FIRST))
				return (0);

			if (!(MODE(nlmp) & RTLD_GLOBAL))
				continue;
			if ((FLAGS(nlmp) & FLG_RT_DELETE) &&
			    ((FLAGS(clmp) & FLG_RT_DELETE) == 0))
				continue;

			sl.sl_imap = nlmp;
			if (LM_LOOKUP_SYM(clmp)(&sl, srp, binfo, in_nfavl))
				return (1);

			/*
			 * Keep track of any global pending lazy loads.
			 */
			lazy += LAZY(nlmp);
		}

		/*
		 * If we're unable to locate the symbol and this link-map list
		 * still has pending lazy dependencies, start loading them in an
		 * attempt to exhaust the search.  Note that as we're already
		 * traversing a dynamic linked list of link-maps there's no
		 * need for elf_lazy_find_sym() to descend the link-maps itself.
		 */
		lml = LIST(lmp);
		if (lazy) {
			DBG_CALL(Dbg_syms_lazy_rescan(lml, name));

			sl.sl_flags |= LKUP_NODESCENT;

			for (nlmp = lmp; nlmp; nlmp = NEXT_RT_MAP(nlmp)) {

				if (!(MODE(nlmp) & RTLD_GLOBAL) || !LAZY(nlmp))
					continue;
				if ((FLAGS(nlmp) & FLG_RT_DELETE) &&
				    ((FLAGS(clmp) & FLG_RT_DELETE) == 0))
					continue;

				sl.sl_imap = nlmp;
				if (elf_lazy_find_sym(&sl, srp, binfo,
				    in_nfavl))
					return (1);
			}
		}
	} else {
		/*
		 * Traverse the dlopen() handle searching all presently loaded
		 * link-maps.
		 */
		Grp_desc	*gdp;
		Aliste		idx;
		uint_t		lazy = 0;

		for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
			nlmp = gdp->gd_depend;

			if ((gdp->gd_flags & GPD_DLSYM) == 0)
				continue;

			sl.sl_imap = nlmp;
			if (LM_LOOKUP_SYM(clmp)(&sl, srp, binfo, in_nfavl))
				return (1);

			if (ghp->gh_flags & GPH_FIRST)
				return (0);

			/*
			 * Keep track of any pending lazy loads associated
			 * with this handle.
			 */
			lazy += LAZY(nlmp);
		}

		/*
		 * If we're unable to locate the symbol and this handle still
		 * has pending lazy dependencies, start loading the lazy
		 * dependencies, in an attempt to exhaust the search.
		 */
		if (lazy) {
			DBG_CALL(Dbg_syms_lazy_rescan(LIST(lmp), name));

			for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
				nlmp = gdp->gd_depend;

				if (((gdp->gd_flags & GPD_DLSYM) == 0) ||
				    (LAZY(nlmp) == 0))
					continue;

				sl.sl_imap = nlmp;
				if (elf_lazy_find_sym(&sl, srp, binfo,
				    in_nfavl))
					return (1);
			}
		}
	}
	return (0);
}

/*
 * Determine whether a symbol resides in a caller.  This may be a reference,
 * which is associated with a specific dependency.
 */
inline static Sym *
sym_lookup_in_caller(Rt_map *clmp, Slookup *slp, Sresult *srp, uint_t *binfo)
{
	if (THIS_IS_ELF(clmp) && SYMINTP(clmp)(slp, srp, binfo, NULL)) {
		Sym	*sym = srp->sr_sym;

		slp->sl_rsymndx = (((ulong_t)sym -
		    (ulong_t)SYMTAB(clmp)) / SYMENT(clmp));
		slp->sl_rsym = sym;
		return (sym);
	}
	return (NULL);
}

/*
 * Core dlsym activity.  Selects symbol lookup method from handle.
 */
static void *
dlsym_core(void *handle, const char *name, Rt_map *clmp, Rt_map **dlmp,
    int *in_nfavl)
{
	Sym		*sym;
	int		ret = 0;
	Syminfo		*sip;
	Slookup		sl;
	Sresult		sr;
	uint_t		binfo;

	/*
	 * Initialize the symbol lookup data structure.
	 *
	 * Standard relocations are evaluated using the symbol index of the
	 * associated relocation symbol.  This index provides for loading
	 * any lazy dependency and establishing a direct binding if necessary.
	 * If a dlsym() operation originates from an object that contains a
	 * symbol table entry for the same name, then we need to establish the
	 * symbol index so that any dependency requirements can be triggered.
	 *
	 * Therefore, the first symbol lookup that is carried out is for the
	 * symbol name within the calling object.  If this symbol exists, the
	 * symbols index is computed, added to the Slookup data, and thus used
	 * to seed the real symbol lookup.
	 */
	SLOOKUP_INIT(sl, name, clmp, clmp, ld_entry_cnt, elf_hash(name),
	    0, 0, 0, LKUP_SYMNDX);
	SRESULT_INIT(sr, name);
	sym = sym_lookup_in_caller(clmp, &sl, &sr, &binfo);

	SRESULT_INIT(sr, name);

	if (sym && (ELF_ST_VISIBILITY(sym->st_other) == STV_SINGLETON)) {
		Rt_map	*hlmp = LIST(clmp)->lm_head;

		/*
		 * If a symbol reference is known, and that reference indicates
		 * that the symbol is a singleton, then the search for the
		 * symbol must follow the default search path.
		 */
		DBG_CALL(Dbg_dl_dlsym(clmp, name, in_nfavl, 0,
		    DBG_DLSYM_SINGLETON));

		sl.sl_imap = hlmp;
		if (handle == RTLD_PROBE)
			sl.sl_flags = LKUP_NOFALLBACK;
		else
			sl.sl_flags = LKUP_SPEC;
		ret = LM_LOOKUP_SYM(clmp)(&sl, &sr, &binfo, in_nfavl);

	} else if (handle == RTLD_NEXT) {
		Rt_map	*nlmp;

		/*
		 * If this handle is RTLD_NEXT determine whether a lazy load
		 * from the caller might provide the next object.  This mimics
		 * the lazy loading initialization normally carried out by
		 * lookup_sym(), however here, we must do this up-front, as
		 * lookup_sym() will be used to inspect the next object.
		 */
		if ((sl.sl_rsymndx) && ((sip = SYMINFO(clmp)) != NULL)) {
			/* LINTED */
			sip = (Syminfo *)((char *)sip +
			    (sl.sl_rsymndx * SYMINENT(clmp)));

			if ((sip->si_flags & SYMINFO_FLG_DIRECT) &&
			    (sip->si_boundto < SYMINFO_BT_LOWRESERVE))
				(void) elf_lazy_load(clmp, &sl,
				    sip->si_boundto, name, 0, NULL, in_nfavl);

			/*
			 * Clear the symbol index, so as not to confuse
			 * lookup_sym() of the next object.
			 */
			sl.sl_rsymndx = 0;
			sl.sl_rsym = NULL;
		}

		/*
		 * If the handle is RTLD_NEXT, start searching in the next link
		 * map from the callers.  Determine permissions from the
		 * present link map.  Indicate to lookup_sym() that we're on an
		 * RTLD_NEXT request so that it will use the callers link map to
		 * start any possible lazy dependency loading.
		 */
		sl.sl_imap = nlmp = NEXT_RT_MAP(clmp);

		DBG_CALL(Dbg_dl_dlsym(clmp, name, in_nfavl,
		    (nlmp ? NAME(nlmp) : MSG_INTL(MSG_STR_NULL)),
		    DBG_DLSYM_NEXT));

		if (nlmp == NULL)
			return (0);

		sl.sl_flags = LKUP_NEXT;
		ret = LM_LOOKUP_SYM(clmp)(&sl, &sr, &binfo, in_nfavl);

	} else if (handle == RTLD_SELF) {
		/*
		 * If the handle is RTLD_SELF start searching from the caller.
		 */
		DBG_CALL(Dbg_dl_dlsym(clmp, name, in_nfavl, NAME(clmp),
		    DBG_DLSYM_SELF));

		sl.sl_imap = clmp;
		sl.sl_flags = (LKUP_SPEC | LKUP_SELF);
		ret = LM_LOOKUP_SYM(clmp)(&sl, &sr, &binfo, in_nfavl);

	} else if (handle == RTLD_DEFAULT) {
		Rt_map	*hlmp = LIST(clmp)->lm_head;

		/*
		 * If the handle is RTLD_DEFAULT mimic the standard symbol
		 * lookup as would be triggered by a relocation.
		 */
		DBG_CALL(Dbg_dl_dlsym(clmp, name, in_nfavl, 0,
		    DBG_DLSYM_DEFAULT));

		sl.sl_imap = hlmp;
		sl.sl_flags = LKUP_SPEC;
		ret = LM_LOOKUP_SYM(clmp)(&sl, &sr, &binfo, in_nfavl);

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
		DBG_CALL(Dbg_dl_dlsym(clmp, name, in_nfavl, 0,
		    DBG_DLSYM_PROBE));

		sl.sl_imap = hlmp;
		sl.sl_flags = LKUP_NOFALLBACK;
		ret = LM_LOOKUP_SYM(clmp)(&sl, &sr, &binfo, in_nfavl);

	} else {
		Grp_hdl *ghp = (Grp_hdl *)handle;

		/*
		 * Look in the shared object specified by the handle and in all
		 * of its dependencies.
		 */
		DBG_CALL(Dbg_dl_dlsym(clmp, name, in_nfavl,
		    NAME(ghp->gh_ownlmp), DBG_DLSYM_DEF));

		ret = LM_DLSYM(clmp)(ghp, &sl, &sr, &binfo, in_nfavl);
	}

	if (ret && ((sym = sr.sr_sym) != NULL)) {
		Lm_list	*lml = LIST(clmp);
		Addr	addr = sym->st_value;

		*dlmp = sr.sr_dmap;
		if (!(FLAGS(*dlmp) & FLG_RT_FIXED))
			addr += ADDR(*dlmp);

		/*
		 * Indicate that the defining object is now used.
		 */
		if (*dlmp != clmp)
			FLAGS1(*dlmp) |= FL1_RT_USED;

		DBG_CALL(Dbg_bind_global(clmp, 0, 0, (Xword)-1, PLT_T_NONE,
		    *dlmp, addr, sym->st_value, sr.sr_name, binfo));

		if ((lml->lm_tflags | AFLAGS(clmp) | AFLAGS(*dlmp)) &
		    LML_TFLG_AUD_SYMBIND) {
			uint_t	sb_flags = LA_SYMB_DLSYM;
			/* LINTED */
			uint_t	symndx = (uint_t)(((Xword)sym -
			    (Xword)SYMTAB(*dlmp)) / SYMENT(*dlmp));
			addr = audit_symbind(clmp, *dlmp, sym, symndx, addr,
			    &sb_flags);
		}
		return ((void *)addr);
	}

	return (NULL);
}

/*
 * Internal dlsym activity.  Called from user level or directly for internal
 * symbol lookup.
 */
void *
dlsym_intn(void *handle, const char *name, Rt_map *clmp, Rt_map **dlmp)
{
	Rt_map		*llmp = NULL;
	void		*error;
	Aliste		idx;
	Grp_desc	*gdp;
	int		in_nfavl = 0;

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
				if ((llmp =
				    LIST(gdp->gd_depend)->lm_tail) != NULL)
					break;
			}
		}
	}

	error = dlsym_core(handle, name, clmp, dlmp, &in_nfavl);

	/*
	 * If the symbol could not be found it is possible that the "not-found"
	 * AVL tree had indicated that a required file does not exist.  In case
	 * the file system has changed since this "not-found" recording was
	 * made, retry the dlsym() with a clean "not-found" AVL tree.
	 */
	if ((error == NULL) && in_nfavl) {
		avl_tree_t	*oavlt = nfavl;

		nfavl = NULL;
		error = dlsym_core(handle, name, clmp, dlmp, NULL);

		/*
		 * If the symbol is found, then any file that was loaded will
		 * have had its full path name registered in the FullPath AVL
		 * tree.  Remove any new "not-found" AVL information, and
		 * restore the former AVL tree.
		 */
		nfavl_remove(nfavl);
		nfavl = oavlt;
	}

	if (error == NULL) {
		/*
		 * Cache the error message, as Java tends to fall through this
		 * code many times.
		 */
		if (nosym_str == NULL)
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
	if (name == NULL) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_ILLSYM));
		return (NULL);
	}
	if ((handle != RTLD_NEXT) && (handle != RTLD_DEFAULT) &&
	    (handle != RTLD_SELF) && (handle != RTLD_PROBE) &&
	    (hdl_validate((Grp_hdl *)handle) == 0)) {
		eprintf(LIST(clmp), ERR_FATAL, MSG_INTL(MSG_ARG_INVHNDL),
		    EC_NATPTR(handle));
		return (NULL);
	}
	return (dlsym_intn(handle, name, clmp, dlmp));
}


#pragma weak _dlsym = dlsym

/*
 * External entry for dlsym().  On success, returns the address of the specified
 * symbol.  On error returns a null.
 */
void *
dlsym(void *handle, const char *name)
{
	int	entry;
	Rt_map	*clmp, *dlmp = NULL;
	void	*addr;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);

	addr = dlsym_check(handle, name, clmp, &dlmp);

	if (entry) {
		if (dlmp)
			is_dep_init(dlmp, clmp);
		leave(LIST(clmp), 0);
	}
	return (addr);
}

/*
 * Core dladdr activity.
 */
static void
dladdr_core(Rt_map *almp, void *addr, Dl_info_t *dlip, void **info, int flags)
{
	/*
	 * Set up generic information and any defaults.
	 */
	dlip->dli_fname = PATHNAME(almp);

	dlip->dli_fbase = (void *)ADDR(almp);
	dlip->dli_sname = NULL;
	dlip->dli_saddr = NULL;

	/*
	 * Determine the nearest symbol to this address.
	 */
	LM_DLADDR(almp)((ulong_t)addr, almp, dlip, info, flags);
}

#pragma weak _dladdr = dladdr

/*
 * External entry for dladdr(3dl) and dladdr1(3dl).  Returns an information
 * structure that reflects the symbol closest to the address specified.
 */
int
dladdr(void *addr, Dl_info_t *dlip)
{
	int	entry, ret;
	Rt_map	*clmp, *almp;
	Lm_list	*clml;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);
	clml = LIST(clmp);

	DBG_CALL(Dbg_dl_dladdr(clmp, addr));

	/*
	 * Use our calling technique to determine what object is associated
	 * with the supplied address.  If a caller can't be determined,
	 * indicate the failure.
	 */
	if ((almp = _caller(addr, CL_NONE)) == NULL) {
		eprintf(clml, ERR_FATAL, MSG_INTL(MSG_ARG_INVADDR),
		    EC_NATPTR(addr));
		ret = 0;
	} else {
		dladdr_core(almp, addr, dlip, 0, 0);
		ret = 1;
	}

	if (entry)
		leave(clml, 0);
	return (ret);
}

#pragma weak _dladdr1 = dladdr1

int
dladdr1(void *addr, Dl_info_t *dlip, void **info, int flags)
{
	int	entry, ret = 1;
	Rt_map	*clmp, *almp;
	Lm_list	*clml;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);
	clml = LIST(clmp);

	DBG_CALL(Dbg_dl_dladdr(clmp, addr));

	/*
	 * Validate any flags.
	 */
	if (flags) {
		int	request;

		if (((request = (flags & RTLD_DL_MASK)) != RTLD_DL_SYMENT) &&
		    (request != RTLD_DL_LINKMAP)) {
			eprintf(clml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLFLAGS),
			    flags);
			ret = 0;

		} else if (info == NULL) {
			eprintf(clml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLINFO),
			    flags);
			ret = 0;
		}
	}

	/*
	 * Use our calling technique to determine what object is associated
	 * with the supplied address.  If a caller can't be determined,
	 * indicate the failure.
	 */
	if (ret) {
		if ((almp = _caller(addr, CL_NONE)) == NULL) {
			eprintf(clml, ERR_FATAL, MSG_INTL(MSG_ARG_INVADDR),
			    EC_NATPTR(addr));
			ret = 0;
		} else
			dladdr_core(almp, addr, dlip, info, flags);
	}

	if (entry)
		leave(clml, 0);
	return (ret);
}

/*
 * Core dldump activity.
 */
static int
dldump_core(Rt_map *clmp, Rt_map *lmp, const char *ipath, const char *opath,
    int flags)
{
	Lm_list	*lml = LIST(clmp);
	Addr	addr = 0;

	/*
	 * Verify any arguments first.
	 */
	if ((opath == NULL) || (opath[0] == '\0') ||
	    ((lmp == NULL) && (ipath[0] == '\0'))) {
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
	if (lmp == NULL) {
		if ((lmp = is_so_loaded(&lml_main, ipath, NULL)) == NULL) {
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
	}

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

#pragma weak _dldump = dldump

/*
 * External entry for dldump(3c).  Returns 0 on success, non-zero otherwise.
 */
int
dldump(const char *ipath, const char *opath, int flags)
{
	int	error, entry;
	Rt_map	*clmp, *lmp;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);

	if (ipath) {
		lmp = NULL;
	} else {
		lmp = lml_main.lm_head;
		ipath = NAME(lmp);
	}

	DBG_CALL(Dbg_dl_dldump(clmp, ipath, opath, flags));

	error = dldump_core(clmp, lmp, ipath, opath, flags);

	if (entry)
		leave(LIST(clmp), 0);
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
 * Set a new deferred dependency name.
 */
static int
set_def_need(Lm_list *lml, Dyninfo *dyip, const char *name)
{
	/*
	 * If this dependency has already been established, then this dlinfo()
	 * call is too late.
	 */
	if (dyip->di_info) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_DEF_DEPLOADED),
		    dyip->di_name);
		return (-1);
	}

	/*
	 * Assign the new dependency name.
	 */
	DBG_CALL(Dbg_file_deferred(lml, dyip->di_name, name));
	dyip->di_flags |= FLG_DI_DEF_DONE;
	dyip->di_name = name;
	return (0);
}

/*
 * Extract information for a dlopen() handle.
 */
static int
dlinfo_core(void *handle, int request, void *p, Rt_map *clmp)
{
	Conv_inv_buf_t	inv_buf;
	char		*handlename;
	Lm_list		*lml = LIST(clmp);
	Rt_map		*lmp = NULL;

	/*
	 * Determine whether a handle is provided.  A handle isn't needed for
	 * all operations, but it is validated here for the initial diagnostic.
	 */
	if (handle == RTLD_SELF) {
		lmp = clmp;
	} else {
		Grp_hdl	*ghp = (Grp_hdl *)handle;

		if (hdl_validate(ghp))
			lmp = ghp->gh_ownlmp;
	}
	if (lmp) {
		handlename = NAME(lmp);
	} else {
		(void) conv_invalid_val(&inv_buf, EC_NATPTR(handle), 0);
		handlename = inv_buf.buf;
	}

	DBG_CALL(Dbg_dl_dlinfo(clmp, handlename, request, p));

	/*
	 * Validate the request and return buffer.
	 */
	if ((request > RTLD_DI_MAX) || (p == NULL)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_ILLVAL));
		return (-1);
	}

	/*
	 * Return configuration cache name and address.
	 */
	if (request == RTLD_DI_CONFIGADDR) {
		Dl_info_t	*dlip = (Dl_info_t *)p;

		if ((config->c_name == NULL) || (config->c_bgn == 0) ||
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
		if (profile_name == NULL) {
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
		if (profile_out == NULL)
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
	if (lmp == NULL) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_ARG_INVHNDL),
		    EC_NATPTR(handle));
		return (-1);
	}

	/*
	 * Obtain the process arguments, environment and auxv.  Note, as the
	 * environment can be modified by the user (putenv(3c)), reinitialize
	 * the environment pointer on each request.
	 */
	if (request == RTLD_DI_ARGSINFO) {
		Dl_argsinfo_t	*aip = (Dl_argsinfo_t *)p;
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
		Spath_desc	sd = { search_rules, NULL, 0 };
		Pdesc		*pdp;
		Dl_serinfo_t	*info;
		Dl_serpath_t	*path;
		char		*strs;
		size_t		size = sizeof (Dl_serinfo_t);
		uint_t		cnt = 0;

		info = (Dl_serinfo_t *)p;
		path = &info->dls_serpath[0];
		strs = (char *)&info->dls_serpath[info->dls_cnt];

		/*
		 * Traverse search path entries for this object.
		 */
		while ((pdp = get_next_dir(&sd, lmp, 0)) != NULL) {
			size_t	_size;

			if (pdp->pd_pname == NULL)
				continue;

			/*
			 * If configuration information exists, it's possible
			 * this path has been identified as non-existent, if so
			 * ignore it.
			 */
			if (pdp->pd_info) {
				Rtc_obj	*dobj = (Rtc_obj *)pdp->pd_info;
				if (dobj->co_flags & RTC_OBJ_NOEXIST)
					continue;
			}

			/*
			 * Keep track of search path count and total info size.
			 */
			if (cnt++)
				size += sizeof (Dl_serpath_t);
			_size = pdp->pd_plen + 1;
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
			(void) strcpy(strs, pdp->pd_pname);
			path->dls_name = strs;
			path->dls_flags = (pdp->pd_flags & LA_SER_MASK);

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

		return (0);
	}

	/*
	 * Return the origin of the object associated with this link-map.
	 * Basically return the dirname(1) of the objects fullpath.
	 */
	if (request == RTLD_DI_ORIGIN) {
		char	*str = (char *)p;

		(void) strncpy(str, ORIGNAME(lmp), DIRSZ(lmp));
		str += DIRSZ(lmp);
		*str = '\0';

		return (0);
	}

	/*
	 * Return the number of object mappings, or the mapping information for
	 * this object.
	 */
	if (request == RTLD_DI_MMAPCNT) {
		uint_t	*cnt = (uint_t *)p;

		*cnt = MMAPCNT(lmp);
		return (0);
	}
	if (request == RTLD_DI_MMAPS) {
		Dl_mapinfo_t	*mip = (Dl_mapinfo_t *)p;

		if (mip->dlm_acnt && mip->dlm_maps) {
			uint_t	cnt = 0;

			while ((cnt < mip->dlm_acnt) && (cnt < MMAPCNT(lmp))) {
				mip->dlm_maps[cnt] = MMAPS(lmp)[cnt];
				cnt++;
			}
			mip->dlm_rcnt = cnt;
		}
		return (0);
	}

	/*
	 * Assign a new dependency name to a deferred dependency.
	 */
	if ((request == RTLD_DI_DEFERRED) ||
	    (request == RTLD_DI_DEFERRED_SYM)) {
		Dl_definfo_t	*dfip = (Dl_definfo_t *)p;
		Dyninfo		*dyip;
		const char	*dname, *rname;

		/*
		 * Verify the names.
		 */
		if ((dfip->dld_refname == NULL) ||
		    (dfip->dld_depname == NULL)) {
			eprintf(LIST(clmp), ERR_FATAL,
			    MSG_INTL(MSG_ARG_ILLNAME));
			return (-1);
		}

		dname = dfip->dld_depname;
		rname = dfip->dld_refname;

		/*
		 * A deferred dependency can be determined by referencing a
		 * symbol family member that is associated to the dependency,
		 * or by looking for the dependency by its name.
		 */
		if (request == RTLD_DI_DEFERRED_SYM) {
			Slookup		sl;
			Sresult		sr;
			uint_t		binfo;
			Syminfo		*sip;

			/*
			 * Lookup the symbol in the associated object.
			 */
			SLOOKUP_INIT(sl, rname, lmp, lmp, ld_entry_cnt,
			    elf_hash(rname), 0, 0, 0, LKUP_SYMNDX);
			SRESULT_INIT(sr, rname);
			if (sym_lookup_in_caller(clmp, &sl, &sr,
			    &binfo) == NULL) {
				eprintf(LIST(clmp), ERR_FATAL,
				    MSG_INTL(MSG_DEF_NOSYMFOUND), rname);
				return (-1);
			}

			/*
			 * Use the symbols index to reference the Syminfo entry
			 * and thus find the associated dependency.
			 */
			if (sl.sl_rsymndx && ((sip = SYMINFO(clmp)) != NULL)) {
				/* LINTED */
				sip = (Syminfo *)((char *)sip +
				    (sl.sl_rsymndx * SYMINENT(lmp)));

				if ((sip->si_flags & SYMINFO_FLG_DEFERRED) &&
				    (sip->si_boundto < SYMINFO_BT_LOWRESERVE) &&
				    ((dyip = DYNINFO(lmp)) != NULL)) {
					dyip += sip->si_boundto;

					if (!(dyip->di_flags & FLG_DI_IGNORE))
						return (set_def_need(lml,
						    dyip, dname));
				}
			}

			/*
			 * No deferred symbol found.
			 */
			eprintf(LIST(clmp), ERR_FATAL,
			    MSG_INTL(MSG_DEF_NOSYMFOUND), rname);
			return (-1);

		} else {
			Dyn	*dyn;

			/*
			 * Using the target objects dependency information, find
			 * the associated deferred dependency.
			 */
			for (dyn = DYN(lmp), dyip = DYNINFO(lmp);
			    !(dyip->di_flags & FLG_DI_IGNORE); dyn++, dyip++) {
				const char	*oname;

				if ((dyip->di_flags & FLG_DI_DEFERRED) == 0)
					continue;

				if (strcmp(rname, dyip->di_name) == 0)
					return (set_def_need(lml, dyip, dname));

				/*
				 * If this dependency name has been changed by
				 * a previous dlinfo(), check the original
				 * dynamic entry string.  The user might be
				 * attempting to re-change an entry using the
				 * original name as the reference.
				 */
				if ((dyip->di_flags & FLG_DI_DEF_DONE) == 0)
					continue;

				oname = STRTAB(lmp) + dyn->d_un.d_val;
				if (strcmp(rname, oname) == 0)
					return (set_def_need(lml, dyip, dname));
			}

			/*
			 * No deferred dependency found.
			 */
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_DEF_NODEPFOUND),
			    rname);
			return (-1);
		}
	}
	return (0);
}

#pragma weak _dlinfo = dlinfo

/*
 * External entry for dlinfo(3dl).
 */
int
dlinfo(void *handle, int request, void *p)
{
	int	error, entry;
	Rt_map	*clmp;

	entry = enter(0);

	clmp = _caller(caller(), CL_EXECDEF);

	error = dlinfo_core(handle, request, p, clmp);

	if (entry)
		leave(LIST(clmp), 0);
	return (error);
}

/*
 * GNU defined function to iterate through the program headers for all
 * currently loaded dynamic objects. The caller supplies a callback function
 * which is called for each object.
 *
 * entry:
 *	callback - Callback function to call. The arguments to the callback
 *		function are:
 *		info - Address of dl_phdr_info structure
 *		size - sizeof (struct dl_phdr_info)
 *		data - Caller supplied value.
 *	data - Value supplied by caller, which is passed to callback without
 *		examination.
 *
 * exit:
 *	callback is called for each dynamic ELF object in the process address
 *	space, halting when a non-zero value is returned, or when the last
 *	object has been processed. The return value from the last call
 *	to callback is returned.
 *
 * note:
 *	The Linux implementation has added additional fields to the
 *	dl_phdr_info structure over time. The callback function is
 *	supposed to use the size field to determine which fields are
 *	present, and to avoid attempts to access non-existent fields.
 *	We have added those fields that are compatible with Solaris, and
 *	which are used by GNU C++ (g++) runtime exception handling support.
 *
 * note:
 *	We issue a callback for every ELF object mapped into the process
 *	address space at the time this routine is entered. These callbacks
 *	are arbitrary functions that can do anything, including possibly
 *	causing new objects to be mapped into the process, or unmapped.
 *	This complicates matters:
 *
 *	-	Adding new objects can cause the alists to be reallocated
 *		or for contents to move. This can happen explicitly via
 *		dlopen(), or implicitly via lazy loading. One might consider
 *		simply banning dlopen from a callback, but lazy loading must
 *		be allowed, in which case there's no reason to ban dlopen().
 *
 *	-	Removing objects can leave us holding references to freed
 *		memory that must not be accessed, and can cause the list
 *		items to move in a way that would cause us to miss reporting
 *		one, or double report others.
 *
 *	-	We cannot allocate memory to build a separate data structure,
 *		because the interface to dl_iterate_phdr() does not have a
 *		way to communicate allocation errors back to the caller.
 *		Even if we could, it would be difficult to do so efficiently.
 *
 *	-	It is possible for dl_iterate_phdr() to be called recursively
 *		from a callback, and there is no way for us to detect or manage
 *		this effectively, particularly as the user might use longjmp()
 *		to skip past us on return. Hence, we must be reentrant
 *		(stateless), further precluding the option of building a
 *		separate data structure.
 *
 *	Despite these constraints, we are able to traverse the link-map
 *	lists safely:
 *
 *	-	Once interposer (preload) objects have been processed at
 *		startup, we know that new objects are always placed at the
 *		end of the list. Hence, if we are reading a list when that
 *		happens, the new object will not alter the part of the list
 *		that we've already processed.
 *
 *	-	The alist _TRAVERSE macros recalculate the address of the
 *		current item from scratch on each iteration, rather than
 *		incrementing a pointer. Hence, alist additions that occur
 *		in mid-traverse will not cause confusion.
 *
 * 	There is one limitation: We cannot continue operation if an object
 *	is removed from the process from within a callback. We detect when
 *	this happens and return immediately with a -1 return value.
 *
 * note:
 *	As currently implemented, if a callback causes an object to be loaded,
 *	that object may or may not be reported by the current invocation of
 *	dl_iterate_phdr(), based on whether or not we have already processed
 *	the link-map list that receives it. If we want to prevent this, it
 *	can be done efficiently by associating the current value of cnt_map
 *	with each new Rt_map entered into the system. Then this function can
 *	use that to detect and skip new objects that enter the system in
 *	mid-iteration. However, the Linux documentation is ambiguous on whether
 *	this is necessary, and it does not appear to matter in practice.
 *	We have therefore chosen not to do so at this time.
 */
int
dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *),
    void *data)
{
	struct dl_phdr_info	info;
	u_longlong_t		l_cnt_map = cnt_map;
	u_longlong_t		l_cnt_unmap = cnt_unmap;
	Lm_list			*lml, *clml;
	Lm_cntl			*lmc;
	Rt_map			*lmp, *clmp;
	Aliste			idx1, idx2;
	Ehdr			*ehdr;
	int			ret = 0;
	int			entry;

	entry = enter(0);
	clmp = _caller(caller(), CL_EXECDEF);
	clml = LIST(clmp);

	DBG_CALL(Dbg_dl_iphdr_enter(clmp, cnt_map, cnt_unmap));

	/* Issue a callback for each ELF object in the process */
	for (APLIST_TRAVERSE(dynlm_list, idx1, lml)) {
		for (ALIST_TRAVERSE(lml->lm_lists, idx2, lmc)) {
			for (lmp = lmc->lc_head; lmp; lmp = NEXT_RT_MAP(lmp)) {
#if defined(_sparc) && !defined(_LP64)
				/*
				 * On 32-bit sparc, the possibility exists that
				 * this object is not ELF.
				 */
				if (THIS_IS_NOT_ELF(lmp))
					continue;
#endif
				/* Prepare the object information structure */
				ehdr = (Ehdr *) ADDR(lmp);
				info.dlpi_addr = (ehdr->e_type == ET_EXEC) ?
				    0 : ADDR(lmp);
				info.dlpi_name = lmp->rt_pathname;
				info.dlpi_phdr = (Phdr *)
				    (ADDR(lmp) + ehdr->e_phoff);
				info.dlpi_phnum = ehdr->e_phnum;
				info.dlpi_adds = cnt_map;
				info.dlpi_subs = cnt_unmap;

				/* Issue the callback */
				DBG_CALL(Dbg_dl_iphdr_callback(clml, &info));
				leave(clml, thr_flg_reenter);
				ret = (* callback)(&info, sizeof (info), data);
				(void) enter(thr_flg_reenter);

				/* Return immediately on non-zero result */
				if (ret != 0)
					goto done;

				/* Adapt to object mapping changes */
				if ((cnt_map == l_cnt_map) &&
				    (cnt_unmap == l_cnt_unmap))
					continue;

				DBG_CALL(Dbg_dl_iphdr_mapchange(clml, cnt_map,
				    cnt_unmap));

				/* Stop if an object was unmapped */
				if (cnt_unmap == l_cnt_unmap) {
					l_cnt_map = cnt_map;
					continue;
				}

				ret = -1;
				DBG_CALL(Dbg_dl_iphdr_unmap_ret(clml));
				goto done;
			}
		}
	}

done:
	if (entry)
		leave(LIST(clmp), 0);
	return (ret);
}
