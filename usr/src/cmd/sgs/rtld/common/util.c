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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * Utility routines for run-time linker.  some are duplicated here from libc
 * (with different names) to avoid name space collisions.
 */
#include	<sys/systeminfo.h>
#include	<stdio.h>
#include	<sys/time.h>
#include	<sys/types.h>
#include	<sys/mman.h>
#include	<sys/lwp.h>
#include	<sys/debug.h>
#include	<stdarg.h>
#include	<fcntl.h>
#include	<string.h>
#include	<dlfcn.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/auxv.h>
#include	<limits.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

/*
 * Null function used as place where a debugger can set a breakpoint.
 */
void
rtld_db_dlactivity(Lm_list *lml)
{
	DBG_CALL(Dbg_util_dbnotify(lml, r_debug.rtd_rdebug.r_rdevent,
	    r_debug.rtd_rdebug.r_state));
}

/*
 * Null function used as place where debugger can set a pre .init
 * processing breakpoint.
 */
void
rtld_db_preinit(Lm_list *lml)
{
	DBG_CALL(Dbg_util_dbnotify(lml, r_debug.rtd_rdebug.r_rdevent,
	    r_debug.rtd_rdebug.r_state));
}

/*
 * Null function used as place where debugger can set a post .init
 * processing breakpoint.
 */
void
rtld_db_postinit(Lm_list *lml)
{
	DBG_CALL(Dbg_util_dbnotify(lml, r_debug.rtd_rdebug.r_rdevent,
	    r_debug.rtd_rdebug.r_state));
}

/*
 * Debugger Event Notification
 *
 * This function centralizes all debugger event notification (ala rtld_db).
 *
 * There's a simple intent, focused on insuring the primary link-map control
 * list (or each link-map list) is consistent, and the indication that objects
 * have been added or deleted from this list.  Although an RD_ADD and RD_DELETE
 * event are posted for each of these, most debuggers don't care, as their
 * view is that these events simply convey an "inconsistent" state.
 *
 * We also don't want to trigger multiple RD_ADD/RD_DELETE events any time we
 * enter ld.so.1.
 *
 * Set an RD_ADD/RD_DELETE event and indicate that an RD_CONSISTENT event is
 * required later (RT_FL_DBNOTIF):
 *
 *  i.	the first time we add or delete an object to the primary link-map
 *	control list.
 *  ii.	the first time we move a secondary link-map control list to the primary
 *	link-map control list (effectively, this is like adding a group of
 *	objects to the primary link-map control list).
 *
 * Set an RD_CONSISTENT event when it is required (RT_FL_DBNOTIF is set):
 *
 *  i.	each time we leave the runtime linker.
 */
void
rd_event(Lm_list *lml, rd_event_e event, r_state_e state)
{
	void	(*fptr)(Lm_list *);

	switch (event) {
	case RD_PREINIT:
		fptr = rtld_db_preinit;
		break;
	case RD_POSTINIT:
		fptr = rtld_db_postinit;
		break;
	case RD_DLACTIVITY:
		switch (state) {
		case RT_CONSISTENT:
			/*
			 * Do we need to send a notification?
			 */
			if ((rtld_flags & RT_FL_DBNOTIF) == 0)
				return;
			rtld_flags &= ~RT_FL_DBNOTIF;
			break;
		case RT_ADD:
		case RT_DELETE:
			/*
			 * If we are already in an inconsistent state, no
			 * notification is required.
			 */
			if (rtld_flags & RT_FL_DBNOTIF)
				return;
			rtld_flags |= RT_FL_DBNOTIF;
			break;
		};
		fptr = rtld_db_dlactivity;
		break;
	default:
		/*
		 * RD_NONE - do nothing
		 */
		break;
	};

	/*
	 * Set event state and call 'notification' function.
	 *
	 * The debugging clients have previously been told about these
	 * notification functions and have set breakpoints on them if they
	 * are interested in the notification.
	 */
	r_debug.rtd_rdebug.r_state = state;
	r_debug.rtd_rdebug.r_rdevent = event;
	fptr(lml);
	r_debug.rtd_rdebug.r_rdevent = RD_NONE;
}

#if	defined(__sparc) || defined(__x86)
/*
 * Stack Cleanup.
 *
 * This function is invoked to 'remove' arguments that were passed in on the
 * stack.  This is most likely if ld.so.1 was invoked directly.  In that case
 * we want to remove ld.so.1 as well as it's arguments from the argv[] array.
 * Which means we then need to slide everything above it on the stack down
 * accordingly.
 *
 * While the stack layout is platform specific - it just so happens that __x86,
 * and __sparc platforms share the following initial stack layout.
 *
 *	!_______________________!  high addresses
 *	!			!
 *	!	Information	!
 *	!	Block		!
 *	!	(size varies)	!
 *	!_______________________!
 *	!	0 word		!
 *	!_______________________!
 *	!	Auxiliary	!
 *	!	vector		!
 *	!	2 word entries	!
 *	!			!
 *	!_______________________!
 *	!	0 word		!
 *	!_______________________!
 *	!	Environment	!
 *	!	pointers	!
 *	!	...		!
 *	!	(one word each)	!
 *	!_______________________!
 *	!	0 word		!
 *	!_______________________!
 *	!	Argument	! low addresses
 *	!	pointers	!
 *	!	Argc words	!
 *	!_______________________!
 *	!			!
 *	!	Argc		!
 *	!_______________________!
 *	!	...		!
 *
 */
static void
stack_cleanup(char **argv, char ***envp, auxv_t **auxv, int rmcnt)
{
	int		ndx;
	long		*argc;
	char		**oargv, **nargv;
	char		**oenvp, **nenvp;
	auxv_t		*oauxv, *nauxv;

	/*
	 * Slide ARGV[] and update argc.  The argv pointer remains the same,
	 * however slide the applications arguments over the arguments to
	 * ld.so.1.
	 */
	nargv = &argv[0];
	oargv = &argv[rmcnt];

	for (ndx = 0; oargv[ndx]; ndx++)
		nargv[ndx] = oargv[ndx];
	nargv[ndx] = oargv[ndx];

	argc = (long *)((uintptr_t)argv - sizeof (long *));
	*argc -= rmcnt;

	/*
	 * Slide ENVP[], and update the environment array pointer.
	 */
	ndx++;
	nenvp = &nargv[ndx];
	oenvp = &oargv[ndx];
	*envp = nenvp;

	for (ndx = 0; oenvp[ndx]; ndx++)
		nenvp[ndx] = oenvp[ndx];
	nenvp[ndx] = oenvp[ndx];

	/*
	 * Slide AUXV[], and update the aux vector pointer.
	 */
	ndx++;
	nauxv = (auxv_t *)&nenvp[ndx];
	oauxv = (auxv_t *)&oenvp[ndx];
	*auxv = nauxv;

	for (ndx = 0; (oauxv[ndx].a_type != AT_NULL); ndx++)
		nauxv[ndx] = oauxv[ndx];
	nauxv[ndx] = oauxv[ndx];
}
#else
/*
 * Verify that the above routine is appropriate for any new platforms.
 */
#error	unsupported architecture!
#endif

/*
 * Compare function for PathNode AVL tree.
 */
static int
pnavl_compare(const void *n1, const void *n2)
{
	uint_t		hash1, hash2;
	const char	*st1, *st2;
	int		rc;

	hash1 = ((PathNode *)n1)->pn_hash;
	hash2 = ((PathNode *)n2)->pn_hash;

	if (hash1 > hash2)
		return (1);
	if (hash1 < hash2)
		return (-1);

	st1 = ((PathNode *)n1)->pn_name;
	st2 = ((PathNode *)n2)->pn_name;

	rc = strcmp(st1, st2);
	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}

/*
 * Create an AVL tree.
 */
static avl_tree_t *
pnavl_create(size_t size)
{
	avl_tree_t	*avlt;

	if ((avlt = malloc(sizeof (avl_tree_t))) == NULL)
		return (NULL);
	avl_create(avlt, pnavl_compare, size, SGSOFFSETOF(PathNode, pn_avl));
	return (avlt);
}

/*
 * Determine whether a PathNode is recorded.
 */
int
pnavl_recorded(avl_tree_t **pnavl, const char *name, uint_t hash,
    avl_index_t *where)
{
	PathNode	pn;

	/*
	 * Create the avl tree if required.
	 */
	if ((*pnavl == NULL) &&
	    ((*pnavl = pnavl_create(sizeof (PathNode))) == NULL))
		return (0);

	pn.pn_name = name;
	if ((pn.pn_hash = hash) == 0)
		pn.pn_hash = sgs_str_hash(name);

	if (avl_find(*pnavl, &pn, where) == NULL)
		return (0);

	return (1);
}

/*
 * Determine if a pathname has already been recorded on the full path name
 * AVL tree.  This tree maintains a node for each path name that ld.so.1 has
 * successfully loaded.  If the path name does not exist in this AVL tree, then
 * the next insertion point is deposited in "where".  This value can be used by
 * fpavl_insert() to expedite the insertion.
 */
Rt_map *
fpavl_recorded(Lm_list *lml, const char *name, uint_t hash, avl_index_t *where)
{
	FullPathNode	fpn, *fpnp;

	/*
	 * Create the avl tree if required.
	 */
	if ((lml->lm_fpavl == NULL) &&
	    ((lml->lm_fpavl = pnavl_create(sizeof (FullPathNode))) == NULL))
		return (NULL);

	fpn.fpn_node.pn_name = name;
	if ((fpn.fpn_node.pn_hash = hash) == 0)
		fpn.fpn_node.pn_hash = sgs_str_hash(name);

	if ((fpnp = avl_find(lml->lm_fpavl, &fpn, where)) == NULL)
		return (NULL);

	return (fpnp->fpn_lmp);
}

/*
 * Insert a name into the FullPathNode AVL tree for the link-map list.  The
 * objects NAME() is the path that would have originally been searched for, and
 * is therefore the name to associate with any "where" value.  If the object has
 * a different PATHNAME(), perhaps because it has resolved to a different file
 * (see fullpath()), then this name will be recorded as a separate FullPathNode
 * (see load_file()).
 */
int
fpavl_insert(Lm_list *lml, Rt_map *lmp, const char *name, avl_index_t where)
{
	FullPathNode	*fpnp;
	uint_t		hash = sgs_str_hash(name);

	if (where == 0) {
		/* LINTED */
		Rt_map	*_lmp = fpavl_recorded(lml, name, hash, &where);

		/*
		 * We better not get a hit now, we do not want duplicates in
		 * the tree.
		 */
		ASSERT(_lmp == NULL);
	}

	/*
	 * Insert new node in tree.
	 */
	if ((fpnp = calloc(sizeof (FullPathNode), 1)) == NULL)
		return (0);

	fpnp->fpn_node.pn_name = name;
	fpnp->fpn_node.pn_hash = hash;
	fpnp->fpn_lmp = lmp;

	if (aplist_append(&FPNODE(lmp), fpnp, AL_CNT_FPNODE) == NULL) {
		free(fpnp);
		return (0);
	}

	ASSERT(lml->lm_fpavl != NULL);
	avl_insert(lml->lm_fpavl, fpnp, where);
	return (1);
}

/*
 * Remove an object from the FullPathNode AVL tree.
 */
void
fpavl_remove(Rt_map *lmp)
{
	FullPathNode	*fpnp;
	Aliste		idx;

	for (APLIST_TRAVERSE(FPNODE(lmp), idx, fpnp)) {
		avl_remove(LIST(lmp)->lm_fpavl, fpnp);
		free(fpnp);
	}
	free(FPNODE(lmp));
	FPNODE(lmp) = NULL;
}

/*
 * Insert a path name into the not-found AVL tree.
 *
 * This tree maintains a node for each path name that ld.so.1 has explicitly
 * inspected, but has failed to load during a single ld.so.1 operation.  If the
 * path name does not exist in this AVL tree, then the next insertion point is
 * deposited in "where".  This value can be used by nfavl_insert() to expedite
 * the insertion.
 */
void
nfavl_insert(const char *name, avl_index_t where)
{
	PathNode	*pnp;
	uint_t		hash = sgs_str_hash(name);

	if (where == 0) {
		/* LINTED */
		int	in_nfavl = pnavl_recorded(&nfavl, name, hash, &where);

		/*
		 * We better not get a hit now, we do not want duplicates in
		 * the tree.
		 */
		ASSERT(in_nfavl == 0);
	}

	/*
	 * Insert new node in tree.
	 */
	if ((pnp = calloc(sizeof (PathNode), 1)) != NULL) {
		pnp->pn_name = name;
		pnp->pn_hash = hash;
		avl_insert(nfavl, pnp, where);
	}
}

/*
 * Insert the directory name, of a full path name, into the secure path AVL
 * tree.
 *
 * This tree is used to maintain a list of directories in which the dependencies
 * of a secure process have been found.  This list provides a fall-back in the
 * case that a $ORIGIN expansion is deemed insecure, when the expansion results
 * in a path name that has already provided dependencies.
 */
void
spavl_insert(const char *name)
{
	char		buffer[PATH_MAX], *str;
	size_t		size;
	avl_index_t	where;
	PathNode	*pnp;
	uint_t		hash;

	/*
	 * Separate the directory name from the path name.
	 */
	if ((str = strrchr(name, '/')) == name)
		size = 1;
	else
		size = str - name;

	(void) strncpy(buffer, name, size);
	buffer[size] = '\0';
	hash = sgs_str_hash(buffer);

	/*
	 * Determine whether this directory name is already recorded, or if
	 * not, 'where" will provide the insertion point for the new string.
	 */
	if (pnavl_recorded(&spavl, buffer, hash, &where))
		return;

	/*
	 * Insert new node in tree.
	 */
	if ((pnp = calloc(sizeof (PathNode), 1)) != NULL) {
		pnp->pn_name = strdup(buffer);
		pnp->pn_hash = hash;
		avl_insert(spavl, pnp, where);
	}
}

/*
 * Inspect the generic string AVL tree for the given string.  If the string is
 * not present, duplicate it, and insert the string in the AVL tree.  Return the
 * duplicated string to the caller.
 *
 * These strings are maintained for the life of ld.so.1 and represent path
 * names, file names, and search paths.  All other AVL trees that maintain
 * FullPathNode and not-found path names use the same string pointer
 * established for this string.
 */
static avl_tree_t	*stravl = NULL;
static char		*strbuf = NULL;
static PathNode		*pnbuf = NULL;
static size_t		strsize = 0, pnsize = 0;

const char *
stravl_insert(const char *name, uint_t hash, size_t nsize, int substr)
{
	char		str[PATH_MAX];
	PathNode	*pnp;
	avl_index_t	where;

	/*
	 * Create the avl tree if required.
	 */
	if ((stravl == NULL) &&
	    ((stravl = pnavl_create(sizeof (PathNode))) == NULL))
		return (NULL);

	/*
	 * Determine the string size if not provided by the caller.
	 */
	if (nsize == 0)
		nsize = strlen(name) + 1;
	else if (substr) {
		/*
		 * The string passed to us may be a multiple path string for
		 * which we only need the first component.  Using the provided
		 * size, strip out the required string.
		 */
		(void) strncpy(str, name, nsize);
		str[nsize - 1] = '\0';
		name = str;
	}

	/*
	 * Allocate a PathNode buffer if one doesn't exist, or any existing
	 * buffer has been used up.
	 */
	if ((pnbuf == NULL) || (sizeof (PathNode) > pnsize)) {
		pnsize = syspagsz;
		if ((pnbuf = dz_map(0, 0, pnsize, (PROT_READ | PROT_WRITE),
		    MAP_PRIVATE)) == MAP_FAILED)
			return (NULL);
	}
	/*
	 * Determine whether this string already exists.
	 */
	pnbuf->pn_name = name;
	if ((pnbuf->pn_hash = hash) == 0)
		pnbuf->pn_hash = sgs_str_hash(name);

	if ((pnp = avl_find(stravl, pnbuf, &where)) != NULL)
		return (pnp->pn_name);

	/*
	 * Allocate a string buffer if one does not exist, or if there is
	 * insufficient space for the new string in any existing buffer.
	 */
	if ((strbuf == NULL) || (nsize > strsize)) {
		strsize = S_ROUND(nsize, syspagsz);

		if ((strbuf = dz_map(0, 0, strsize, (PROT_READ | PROT_WRITE),
		    MAP_PRIVATE)) == MAP_FAILED)
			return (NULL);
	}

	(void) memcpy(strbuf, name, nsize);
	pnp = pnbuf;
	pnp->pn_name = strbuf;
	avl_insert(stravl, pnp, where);

	strbuf += nsize;
	strsize -= nsize;
	pnbuf++;
	pnsize -= sizeof (PathNode);
	return (pnp->pn_name);
}

/*
 * Prior to calling an object, either via a .plt or through dlsym(), make sure
 * its .init has fired.  Through topological sorting, ld.so.1 attempts to fire
 * init's in the correct order, however, this order is typically based on needed
 * dependencies and non-lazy relocation bindings.  Lazy relocations (.plts) can
 * still occur and result in bindings that were not captured during topological
 * sorting.  This routine compensates for this lack of binding information, and
 * provides for dynamic .init firing.
 */
void
is_dep_init(Rt_map *dlmp, Rt_map *clmp)
{
	Rt_map	**tobj;

	/*
	 * If the caller is an auditor, and the destination isn't, then don't
	 * run any .inits (see comments in load_completion()).
	 */
	if ((LIST(clmp)->lm_tflags & LML_TFLG_NOAUDIT) &&
	    ((LIST(dlmp)->lm_tflags & LML_TFLG_NOAUDIT) == 0))
		return;

	if ((dlmp == clmp) || (rtld_flags & RT_FL_INITFIRST))
		return;

	rt_mutex_lock(&dlmp->rt_lock);
	while (dlmp->rt_init_thread != rt_thr_self() && (FLAGS(dlmp) &
	    (FLG_RT_RELOCED | FLG_RT_INITCALL | FLG_RT_INITDONE)) ==
	    (FLG_RT_RELOCED | FLG_RT_INITCALL)) {
		leave(LIST(dlmp), 0);
		(void) _lwp_cond_wait(&dlmp->rt_cv, (mutex_t *)&dlmp->rt_lock);
		rt_mutex_unlock(&dlmp->rt_lock);
		(void) enter(0);
		rt_mutex_lock(&dlmp->rt_lock);
	}
	rt_mutex_unlock(&dlmp->rt_lock);

	if ((FLAGS(dlmp) & (FLG_RT_RELOCED | FLG_RT_INITDONE)) ==
	    (FLG_RT_RELOCED | FLG_RT_INITDONE))
		return;

	if ((tobj = calloc(2, sizeof (Rt_map *))) != NULL) {
		tobj[0] = dlmp;
		call_init(tobj, DBG_INIT_DYN);
	}
}

/*
 * Execute .{preinit|init|fini}array sections
 */
void
call_array(Addr *array, uint_t arraysz, Rt_map *lmp, Word shtype)
{
	int	start, stop, incr, ndx;
	uint_t	arraycnt = (uint_t)(arraysz / sizeof (Addr));

	if (array == NULL)
		return;

	/*
	 * initarray & preinitarray are walked from beginning to end - while
	 * finiarray is walked from end to beginning.
	 */
	if (shtype == SHT_FINI_ARRAY) {
		start = arraycnt - 1;
		stop = incr = -1;
	} else {
		start = 0;
		stop = arraycnt;
		incr = 1;
	}

	/*
	 * Call the .*array[] entries
	 */
	for (ndx = start; ndx != stop; ndx += incr) {
		uint_t	rtldflags;
		void	(*fptr)(void) = (void(*)())array[ndx];

		DBG_CALL(Dbg_util_call_array(lmp, (void *)fptr, ndx, shtype));

		APPLICATION_ENTER(rtldflags);
		leave(LIST(lmp), 0);
		(*fptr)();
		(void) enter(0);
		APPLICATION_RETURN(rtldflags);
	}
}

/*
 * Execute any .init sections.  These are passed to us in an lmp array which
 * (by default) will have been sorted.
 */
void
call_init(Rt_map **tobj, int flag)
{
	Rt_map		**_tobj, **_nobj;
	static APlist	*pending = NULL;

	/*
	 * If we're in the middle of an INITFIRST, this must complete before
	 * any new init's are fired.  In this case add the object list to the
	 * pending queue and return.  We'll pick up the queue after any
	 * INITFIRST objects have their init's fired.
	 */
	if (rtld_flags & RT_FL_INITFIRST) {
		(void) aplist_append(&pending, tobj, AL_CNT_PENDING);
		return;
	}

	/*
	 * Traverse the tobj array firing each objects init.
	 */
	for (_tobj = _nobj = tobj, _nobj++; *_tobj != NULL; _tobj++, _nobj++) {
		Rt_map	*lmp = *_tobj;
		void	(*iptr)() = INIT(lmp);

		if (FLAGS(lmp) & FLG_RT_INITCALL)
			continue;

		FLAGS(lmp) |= FLG_RT_INITCALL;
		lmp->rt_init_thread = rt_thr_self();

		/*
		 * Establish an initfirst state if necessary - no other inits
		 * will be fired (because of additional relocation bindings)
		 * when in this state.
		 */
		if (FLAGS(lmp) & FLG_RT_INITFRST)
			rtld_flags |= RT_FL_INITFIRST;

		if (INITARRAY(lmp) || iptr)
			DBG_CALL(Dbg_util_call_init(lmp, flag));

		if (iptr) {
			uint_t	rtldflags;

			APPLICATION_ENTER(rtldflags);
			leave(LIST(lmp), 0);
			(*iptr)();
			(void) enter(0);
			APPLICATION_RETURN(rtldflags);
		}

		call_array(INITARRAY(lmp), INITARRAYSZ(lmp), lmp,
		    SHT_INIT_ARRAY);

		if (INITARRAY(lmp) || iptr)
			DBG_CALL(Dbg_util_call_init(lmp, DBG_INIT_DONE));

		/*
		 * Set the initdone flag regardless of whether this object
		 * actually contains an .init section.  This flag prevents us
		 * from processing this section again for an .init and also
		 * signifies that a .fini must be called should it exist.
		 * Clear the sort field for use in later .fini processing.
		 */
		rt_mutex_lock(&lmp->rt_lock);
		FLAGS(lmp) |= FLG_RT_INITDONE;
		lmp->rt_init_thread = (thread_t)0;
		_lwp_cond_broadcast(&lmp->rt_cv);
		rt_mutex_unlock(&lmp->rt_lock);
		SORTVAL(lmp) = -1;

		/*
		 * If we're firing an INITFIRST object, and other objects must
		 * be fired which are not INITFIRST, make sure we grab any
		 * pending objects that might have been delayed as this
		 * INITFIRST was processed.
		 */
		if ((rtld_flags & RT_FL_INITFIRST) &&
		    ((*_nobj == NULL) || !(FLAGS(*_nobj) & FLG_RT_INITFRST))) {
			Aliste	idx;
			Rt_map	**pobj;

			rtld_flags &= ~RT_FL_INITFIRST;

			for (APLIST_TRAVERSE(pending, idx, pobj)) {
				aplist_delete(pending, &idx);
				call_init(pobj, DBG_INIT_PEND);
			}
		}
	}
	free(tobj);
}

/*
 * Call .fini sections for the topologically sorted list of objects.  This
 * routine is called from remove_hdl() for any objects being torn down as part
 * of a dlclose() operation, and from atexit() processing for all the remaining
 * objects within the process.
 */
void
call_fini(Lm_list *lml, Rt_map **tobj, Rt_map *clmp)
{
	Rt_map **_tobj;

	for (_tobj = tobj; *_tobj != NULL; _tobj++) {
		Rt_map		*lmp = *_tobj;

		/*
		 * Only fire a .fini if the objects corresponding .init has
		 * completed.  We collect all .fini sections of objects that
		 * had their .init collected, but that doesn't mean that at
		 * the time of collection, that the .init had completed.
		 */
		if (FLAGS(lmp) & FLG_RT_INITDONE) {
			void	(*fptr)(void) = FINI(lmp);

			if (FINIARRAY(lmp) || fptr)
				DBG_CALL(Dbg_util_call_fini(lmp));

			call_array(FINIARRAY(lmp), FINIARRAYSZ(lmp), lmp,
			    SHT_FINI_ARRAY);

			if (fptr) {
				uint_t	rtldflags;

				APPLICATION_ENTER(rtldflags);
				leave(lml, 0);
				(*fptr)();
				(void) enter(0);
				APPLICATION_RETURN(rtldflags);
			}
		}

		/*
		 * Skip main, this is explicitly called last in atexit_fini().
		 */
		if (FLAGS(lmp) & FLG_RT_ISMAIN)
			continue;

		/*
		 * This object has exercised its last instructions (regardless
		 * of whether it will be unmapped or not).  Audit this closure.
		 */
		if ((lml->lm_tflags & LML_TFLG_NOAUDIT) == 0)
			audit_objclose(lmp, clmp);
	}

	DBG_CALL(Dbg_bind_plt_summary(lml, M_MACH, pltcnt21d, pltcnt24d,
	    pltcntu32, pltcntu44, pltcntfull, pltcntfar));

	free(tobj);
}

/*
 * Function called by atexit(3C).  Calls all .fini sections within the objects
 * that make up the process.  As .fini processing is the last opportunity for
 * any new bindings to be established, this is also a convenient location to
 * check for unused objects.
 */
void
atexit_fini()
{
	Rt_map	**tobj, *lmp;
	Lm_list	*lml;
	Aliste	idx;

	(void) enter(0);

	rtld_flags |= RT_FL_ATEXIT;

	lml = &lml_main;
	lml->lm_flags |= LML_FLG_ATEXIT;
	lml->lm_flags &= ~LML_FLG_INTRPOSETSORT;
	lmp = (Rt_map *)lml->lm_head;

	/*
	 * Reverse topologically sort the main link-map for .fini execution.
	 */
	if (((tobj = tsort(lmp, lml->lm_obj, RT_SORT_FWD)) != NULL) &&
	    (tobj != (Rt_map **)S_ERROR))
		call_fini(lml, tobj, NULL);

	/*
	 * Now that all .fini code has been run, see what unreferenced objects
	 * remain.
	 */
	unused(lml);

	/*
	 * Traverse any alternative link-map lists, looking for non-auditors.
	 */
	for (APLIST_TRAVERSE(dynlm_list, idx, lml)) {
		/*
		 * Ignore the base-link-map list, which has already been
		 * processed, the runtime linkers link-map list, which is
		 * processed last, and any auditors.
		 */
		if ((lml->lm_flags & (LML_FLG_BASELM | LML_FLG_RTLDLM)) ||
		    (lml->lm_tflags & LML_TFLG_AUD_MASK) ||
		    ((lmp = (Rt_map *)lml->lm_head) == NULL))
			continue;

		lml->lm_flags |= LML_FLG_ATEXIT;
		lml->lm_flags &= ~LML_FLG_INTRPOSETSORT;

		/*
		 * Reverse topologically sort the link-map for .fini execution.
		 */
		if (((tobj = tsort(lmp, lml->lm_obj, RT_SORT_FWD)) != NULL) &&
		    (tobj != (Rt_map **)S_ERROR))
			call_fini(lml, tobj, NULL);

		unused(lml);
	}

	/*
	 * Add an explicit close to main and ld.so.1.  Although main's .fini is
	 * collected in call_fini() to provide for FINITARRAY processing, its
	 * audit_objclose is explicitly skipped.  This provides for it to be
	 * called last, here.  This is the reverse of the explicit calls to
	 * audit_objopen() made in setup().
	 */
	lml = &lml_main;
	lmp = (Rt_map *)lml->lm_head;

	if ((lml->lm_tflags | AFLAGS(lmp)) & LML_TFLG_AUD_MASK) {
		audit_objclose((Rt_map *)lml_rtld.lm_head, lmp);
		audit_objclose(lmp, lmp);
	}

	/*
	 * Traverse any alternative link-map lists, looking for non-auditors.
	 */
	for (APLIST_TRAVERSE(dynlm_list, idx, lml)) {
		/*
		 * Ignore the base-link-map list, which has already been
		 * processed, the runtime linkers link-map list, which is
		 * processed last, and any non-auditors.
		 */
		if ((lml->lm_flags & (LML_FLG_BASELM | LML_FLG_RTLDLM)) ||
		    ((lml->lm_tflags & LML_TFLG_AUD_MASK) == 0) ||
		    ((lmp = (Rt_map *)lml->lm_head) == NULL))
			continue;

		lml->lm_flags |= LML_FLG_ATEXIT;
		lml->lm_flags &= ~LML_FLG_INTRPOSETSORT;

		/*
		 * Reverse topologically sort the link-map for .fini execution.
		 */
		if (((tobj = tsort(lmp, lml->lm_obj, RT_SORT_FWD)) != NULL) &&
		    (tobj != (Rt_map **)S_ERROR))
			call_fini(lml, tobj, NULL);

		unused(lml);
	}

	/*
	 * Finally reverse topologically sort the runtime linkers link-map for
	 * .fini execution.
	 */
	lml = &lml_rtld;
	lml->lm_flags |= LML_FLG_ATEXIT;
	lml->lm_flags &= ~LML_FLG_INTRPOSETSORT;
	lmp = (Rt_map *)lml->lm_head;

	if (((tobj = tsort(lmp, lml->lm_obj, RT_SORT_FWD)) != NULL) &&
	    (tobj != (Rt_map **)S_ERROR))
		call_fini(lml, tobj, NULL);

	leave(&lml_main, 0);
}

/*
 * This routine is called to complete any runtime linker activity which may have
 * resulted in objects being loaded.  This is called from all user entry points
 * and from any internal dl*() requests.
 */
void
load_completion(Rt_map *nlmp)
{
	Rt_map	**tobj = NULL;
	Lm_list	*nlml;

	/*
	 * Establish any .init processing.  Note, in a world of lazy loading,
	 * objects may have been loaded regardless of whether the users request
	 * was fulfilled (i.e., a dlsym() request may have failed to find a
	 * symbol but objects might have been loaded during its search).  Thus,
	 * any tsorting starts from the nlmp (new link-maps) pointer and not
	 * necessarily from the link-map that may have satisfied the request.
	 *
	 * Note, the primary link-map has an initialization phase where dynamic
	 * .init firing is suppressed.  This provides for a simple and clean
	 * handshake with the primary link-maps libc, which is important for
	 * establishing uberdata.  In addition, auditors often obtain handles
	 * to primary link-map objects as the objects are loaded, so as to
	 * inspect the link-map for symbols.  This inspection is allowed without
	 * running any code on the primary link-map, as running this code may
	 * reenter the auditor, who may not yet have finished its own
	 * initialization.
	 */
	if (nlmp)
		nlml = LIST(nlmp);

	if (nlmp && nlml->lm_init && ((nlml != &lml_main) ||
	    (rtld_flags2 & (RT_FL2_PLMSETUP | RT_FL2_NOPLM)))) {
		if ((tobj = tsort(nlmp, nlml->lm_init,
		    RT_SORT_REV)) == (Rt_map **)S_ERROR)
			tobj = NULL;
	}

	/*
	 * Make sure any alternative link-map retrieves any external interfaces
	 * and initializes threads.
	 */
	if (nlmp && (nlml != &lml_main)) {
		(void) rt_get_extern(nlml, nlmp);
		rt_thr_init(nlml);
	}

	/*
	 * Traverse the list of new link-maps and register any dynamic TLS.
	 * This storage is established for any objects not on the primary
	 * link-map, and for any objects added to the primary link-map after
	 * static TLS has been registered.
	 */
	if (nlmp && nlml->lm_tls && ((nlml != &lml_main) ||
	    (rtld_flags2 & (RT_FL2_PLMSETUP | RT_FL2_NOPLM)))) {
		Rt_map	*lmp;

		for (lmp = nlmp; lmp; lmp = NEXT_RT_MAP(lmp)) {
			if (PTTLS(lmp) && PTTLS(lmp)->p_memsz)
				tls_modaddrem(lmp, TM_FLG_MODADD);
		}
		nlml->lm_tls = 0;
	}

	/*
	 * Fire any .init's.
	 */
	if (tobj)
		call_init(tobj, DBG_INIT_SORT);
}

/*
 * Append an item to the specified link map control list.
 */
void
lm_append(Lm_list *lml, Aliste lmco, Rt_map *lmp)
{
	Lm_cntl	*lmc;
	int	add = 1;

	/*
	 * Indicate that this link-map list has a new object.
	 */
	(lml->lm_obj)++;

	/*
	 * If we're about to add a new object to the main link-map control
	 * list, alert the debuggers.  Additions of individual objects to the
	 * main link-map control list occur during initial setup as the
	 * applications immediate dependencies are loaded.  Additional objects
	 * are loaded on the main link-map control list after they have been
	 * fully initialized on an alternative link-map control list.  See
	 * lm_move().
	 */
	if (lmco == ALIST_OFF_DATA)
		rd_event(lml, RD_DLACTIVITY, RT_ADD);

	/* LINTED */
	lmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, lmco);

	/*
	 * A link-map list header points to one of more link-map control lists
	 * (see include/rtld.h).  The initial list, pointed to by lm_cntl, is
	 * the list of relocated objects.  Other lists maintain objects that
	 * are still being analyzed or relocated.  This list provides the core
	 * link-map list information used by all ld.so.1 routines.
	 */
	if (lmc->lc_head == NULL) {
		/*
		 * If this is the first link-map for the given control list,
		 * initialize the list.
		 */
		lmc->lc_head = lmc->lc_tail = lmp;
		add = 0;

	} else if (FLAGS(lmp) & FLG_RT_OBJINTPO) {
		Rt_map	*tlmp;

		/*
		 * If this is an interposer then append the link-map following
		 * any other interposers (these are objects that have been
		 * previously preloaded, or were identified with -z interpose).
		 * Interposers can only be inserted on the first link-map
		 * control list, as once relocation has started, interposition
		 * from new interposers can't be guaranteed.
		 *
		 * NOTE: We do not interpose on the head of a list.  This model
		 * evolved because dynamic executables have already been fully
		 * relocated within themselves and thus can't be interposed on.
		 * Nowadays it's possible to have shared objects at the head of
		 * a list, which conceptually means they could be interposed on.
		 * But, shared objects can be created via dldump() and may only
		 * be partially relocated (just relatives), in which case they
		 * are interposable, but are marked as fixed (ET_EXEC).
		 *
		 * Thus we really don't have a clear method of deciding when the
		 * head of a link-map is interposable.  So, to be consistent,
		 * for now only add interposers after the link-map lists head
		 * object.
		 */
		for (tlmp = NEXT_RT_MAP(lmc->lc_head); tlmp;
		    tlmp = NEXT_RT_MAP(tlmp)) {

			if (FLAGS(tlmp) & FLG_RT_OBJINTPO)
				continue;

			/*
			 * Insert the new link-map before this non-interposer,
			 * and indicate an interposer is found.
			 */
			NEXT(PREV_RT_MAP(tlmp)) = (Link_map *)lmp;
			PREV(lmp) = PREV(tlmp);

			NEXT(lmp) = (Link_map *)tlmp;
			PREV(tlmp) = (Link_map *)lmp;

			lmc->lc_flags |= LMC_FLG_REANALYZE;
			add = 0;
			break;
		}
	}

	/*
	 * Fall through to appending the new link map to the tail of the list.
	 * If we're processing the initial objects of this link-map list, add
	 * them to the backward compatibility list.
	 */
	if (add) {
		NEXT(lmc->lc_tail) = (Link_map *)lmp;
		PREV(lmp) = (Link_map *)lmc->lc_tail;
		lmc->lc_tail = lmp;
	}

	/*
	 * Having added this link-map to a control list, indicate which control
	 * list the link-map belongs to.  Note, control list information is
	 * always maintained as an offset, as the Alist can be reallocated.
	 */
	CNTL(lmp) = lmco;

	/*
	 * Indicate if an interposer is found.  Note that the first object on a
	 * link-map can be explicitly defined as an interposer so that it can
	 * provide interposition over direct binding requests.
	 */
	if (FLAGS(lmp) & MSK_RT_INTPOSE)
		lml->lm_flags |= LML_FLG_INTRPOSE;

	/*
	 * For backward compatibility with debuggers, the link-map list contains
	 * pointers to the main control list.
	 */
	if (lmco == ALIST_OFF_DATA) {
		lml->lm_head = lmc->lc_head;
		lml->lm_tail = lmc->lc_tail;
	}
}

/*
 * Delete an item from the specified link map control list.
 */
void
lm_delete(Lm_list *lml, Rt_map *lmp, Rt_map *clmp)
{
	Lm_cntl	*lmc;

	/*
	 * If the control list pointer hasn't been initialized, this object
	 * never got added to a link-map list.
	 */
	if (CNTL(lmp) == 0)
		return;

	/*
	 * If we're about to delete an object from the main link-map control
	 * list, alert the debuggers.
	 */
	if (CNTL(lmp) == ALIST_OFF_DATA)
		rd_event(lml, RD_DLACTIVITY, RT_DELETE);

	/*
	 * If we're being audited tell the audit library that we're
	 * about to go deleting dependencies.
	 */
	if (clmp && (aud_activity ||
	    ((LIST(clmp)->lm_tflags | AFLAGS(clmp)) & LML_TFLG_AUD_ACTIVITY)))
		audit_activity(clmp, LA_ACT_DELETE);

	/* LINTED */
	lmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, CNTL(lmp));

	if (lmc->lc_head == lmp)
		lmc->lc_head = NEXT_RT_MAP(lmp);
	else
		NEXT(PREV_RT_MAP(lmp)) = (void *)NEXT(lmp);

	if (lmc->lc_tail == lmp)
		lmc->lc_tail = PREV_RT_MAP(lmp);
	else
		PREV(NEXT_RT_MAP(lmp)) = PREV(lmp);

	/*
	 * For backward compatibility with debuggers, the link-map list contains
	 * pointers to the main control list.
	 */
	if (lmc == (Lm_cntl *)&lml->lm_lists->al_data) {
		lml->lm_head = lmc->lc_head;
		lml->lm_tail = lmc->lc_tail;
	}

	/*
	 * Indicate we have one less object on this control list.
	 */
	(lml->lm_obj)--;
}

/*
 * Move a link-map control list to another.  Objects that are being relocated
 * are maintained on secondary control lists.  Once their relocation is
 * complete, the entire list is appended to the previous control list, as this
 * list must have been the trigger for generating the new control list.
 */
void
lm_move(Lm_list *lml, Aliste nlmco, Aliste plmco, Lm_cntl *nlmc, Lm_cntl *plmc)
{
	Rt_map	*lmp;

	/*
	 * If we're about to add a new family of objects to the main link-map
	 * control list, alert the debuggers.  Additions of object families to
	 * the main link-map control list occur during lazy loading, filtering
	 * and dlopen().
	 */
	if (plmco == ALIST_OFF_DATA)
		rd_event(lml, RD_DLACTIVITY, RT_ADD);

	DBG_CALL(Dbg_file_cntl(lml, nlmco, plmco));

	/*
	 * Indicate each new link-map has been moved to the previous link-map
	 * control list.
	 */
	for (lmp = nlmc->lc_head; lmp; lmp = NEXT_RT_MAP(lmp)) {
		CNTL(lmp) = plmco;

		/*
		 * If these objects are being added to the main link-map
		 * control list, indicate that there are init's available
		 * for harvesting.
		 */
		if (plmco == ALIST_OFF_DATA) {
			lml->lm_init++;
			lml->lm_flags |= LML_FLG_OBJADDED;
		}
	}

	/*
	 * Move the new link-map control list, to the callers link-map control
	 * list.
	 */
	if (plmc->lc_head == NULL) {
		plmc->lc_head = nlmc->lc_head;
		PREV(nlmc->lc_head) = NULL;
	} else {
		NEXT(plmc->lc_tail) = (Link_map *)nlmc->lc_head;
		PREV(nlmc->lc_head) = (Link_map *)plmc->lc_tail;
	}

	plmc->lc_tail = nlmc->lc_tail;
	nlmc->lc_head = nlmc->lc_tail = NULL;

	/*
	 * For backward compatibility with debuggers, the link-map list contains
	 * pointers to the main control list.
	 */
	if (plmco == ALIST_OFF_DATA) {
		lml->lm_head = plmc->lc_head;
		lml->lm_tail = plmc->lc_tail;
	}
}

/*
 * Create, or assign a link-map control list.  Each link-map list contains a
 * main control list, which has an Alist offset of ALIST_OFF_DATA (see the
 * description in include/rtld.h).  During the initial construction of a
 * process, objects are added to this main control list.  This control list is
 * never deleted, unless an alternate link-map list has been requested (say for
 * auditors), and the associated objects could not be loaded or relocated.
 *
 * Once relocation has started, any lazy loadable objects, or filtees, are
 * processed on a new, temporary control list.  Only when these objects have
 * been fully relocated, are they moved to the main link-map control list.
 * Once the objects are moved, this temporary control list is deleted (see
 * remove_cntl()).
 *
 * A dlopen() always requires a new temporary link-map control list.
 * Typically, a dlopen() occurs on a link-map list that had already started
 * relocation, however, auditors can dlopen() objects on the main link-map
 * list while under initial construction, before any relocation has begun.
 * Hence, dlopen() requests are explicitly flagged.
 */
Aliste
create_cntl(Lm_list *lml, int dlopen)
{
	/*
	 * If the head link-map object has already been relocated, create a
	 * new, temporary, control list.
	 */
	if (dlopen || (lml->lm_head == NULL) ||
	    (FLAGS(lml->lm_head) & FLG_RT_RELOCED)) {
		Lm_cntl *lmc;

		if ((lmc = alist_append(&lml->lm_lists, NULL, sizeof (Lm_cntl),
		    AL_CNT_LMLISTS)) == NULL)
			return (NULL);

		return ((Aliste)((char *)lmc - (char *)lml->lm_lists));
	}

	return (ALIST_OFF_DATA);
}

/*
 * Environment variables can have a variety of defined permutations, and thus
 * the following infrastructure exists to allow this variety and to select the
 * required definition.
 *
 * Environment variables can be defined as 32- or 64-bit specific, and if so
 * they will take precedence over any instruction set neutral form.  Typically
 * this is only useful when the environment value is an informational string.
 *
 * Environment variables may be obtained from the standard user environment or
 * from a configuration file.  The latter provides a fallback if no user
 * environment setting is found, and can take two forms:
 *
 *  -	a replaceable definition - this will be used if no user environment
 *	setting has been seen, or
 *
 *  -	an permanent definition - this will be used no matter what user
 *	environment setting is seen.  In the case of list variables it will be
 *	appended to any process environment setting seen.
 *
 * Environment variables can be defined without a value (ie. LD_XXXX=) so as to
 * override any replaceable environment variables from a configuration file.
 */
static	u_longlong_t		rplgen = 0;	/* replaceable generic */
						/*	variables */
static	u_longlong_t		rplisa = 0;	/* replaceable ISA specific */
						/*	variables */
static	u_longlong_t		prmgen = 0;	/* permanent generic */
						/*	variables */
static	u_longlong_t		prmisa = 0;	/* permanent ISA specific */
						/*	variables */
static	u_longlong_t		cmdgen = 0;	/* command line (-e) generic */
						/*	variables */
static	u_longlong_t		cmdisa = 0;	/* command line (-e) ISA */
						/*	specific variables */

/*
 * Classify an environment variables type.
 */
#define	ENV_TYP_IGNORE		0x01		/* ignore - variable is for */
						/*	the wrong ISA */
#define	ENV_TYP_ISA		0x02		/* variable is ISA specific */
#define	ENV_TYP_CONFIG		0x04		/* variable obtained from a */
						/*	config file */
#define	ENV_TYP_PERMANT		0x08		/* variable is permanent */
#define	ENV_TYP_CMDLINE		0x10		/* variable provide with -e */
#define	ENV_TYP_NULL		0x20		/* variable is null */

/*
 * Identify all environment variables.
 */
#define	ENV_FLG_AUDIT		0x0000000000001ULL
#define	ENV_FLG_AUDIT_ARGS	0x0000000000002ULL
#define	ENV_FLG_BIND_NOW	0x0000000000004ULL
#define	ENV_FLG_BIND_NOT	0x0000000000008ULL
#define	ENV_FLG_BINDINGS	0x0000000000010ULL
#define	ENV_FLG_CONFGEN		0x0000000000020ULL
#define	ENV_FLG_CONFIG		0x0000000000040ULL
#define	ENV_FLG_DEBUG		0x0000000000080ULL
#define	ENV_FLG_DEBUG_OUTPUT	0x0000000000100ULL
#define	ENV_FLG_DEMANGLE	0x0000000000200ULL
#define	ENV_FLG_FLAGS		0x0000000000400ULL
#define	ENV_FLG_INIT		0x0000000000800ULL
#define	ENV_FLG_LIBPATH		0x0000000001000ULL
#define	ENV_FLG_LOADAVAIL	0x0000000002000ULL
#define	ENV_FLG_LOADFLTR	0x0000000004000ULL
#define	ENV_FLG_NOAUDIT		0x0000000008000ULL
#define	ENV_FLG_NOAUXFLTR	0x0000000010000ULL
#define	ENV_FLG_NOBAPLT		0x0000000020000ULL
#define	ENV_FLG_NOCONFIG	0x0000000040000ULL
#define	ENV_FLG_NODIRCONFIG	0x0000000080000ULL
#define	ENV_FLG_NODIRECT	0x0000000100000ULL
#define	ENV_FLG_NOENVCONFIG	0x0000000200000ULL
#define	ENV_FLG_NOLAZY		0x0000000400000ULL
#define	ENV_FLG_NOOBJALTER	0x0000000800000ULL
#define	ENV_FLG_NOVERSION	0x0000001000000ULL
#define	ENV_FLG_PRELOAD		0x0000002000000ULL
#define	ENV_FLG_PROFILE		0x0000004000000ULL
#define	ENV_FLG_PROFILE_OUTPUT	0x0000008000000ULL
#define	ENV_FLG_SIGNAL		0x0000010000000ULL
#define	ENV_FLG_TRACE_OBJS	0x0000020000000ULL
#define	ENV_FLG_TRACE_PTHS	0x0000040000000ULL
#define	ENV_FLG_UNREF		0x0000080000000ULL
#define	ENV_FLG_UNUSED		0x0000100000000ULL
#define	ENV_FLG_VERBOSE		0x0000200000000ULL
#define	ENV_FLG_WARN		0x0000400000000ULL
#define	ENV_FLG_NOFLTCONFIG	0x0000800000000ULL
#define	ENV_FLG_BIND_LAZY	0x0001000000000ULL
#define	ENV_FLG_NOUNRESWEAK	0x0002000000000ULL
#define	ENV_FLG_NOPAREXT	0x0004000000000ULL
#define	ENV_FLG_HWCAP		0x0008000000000ULL
#define	ENV_FLG_SFCAP		0x0010000000000ULL
#define	ENV_FLG_MACHCAP		0x0020000000000ULL
#define	ENV_FLG_PLATCAP		0x0040000000000ULL
#define	ENV_FLG_CAP_FILES	0x0080000000000ULL
#define	ENV_FLG_DEFERRED	0x0100000000000ULL
#define	ENV_FLG_NOENVIRON	0x0200000000000ULL
#define	ENV_FLG_TOXICPATH	0x0400000000000ULL

#define	SEL_REPLACE		0x0001
#define	SEL_PERMANT		0x0002
#define	SEL_ACT_RT		0x0100	/* setting rtld_flags */
#define	SEL_ACT_RT2		0x0200	/* setting rtld_flags2 */
#define	SEL_ACT_STR		0x0400	/* setting string value */
#define	SEL_ACT_LML		0x0800	/* setting lml_flags */
#define	SEL_ACT_LMLT		0x1000	/* setting lml_tflags */
#define	SEL_ACT_SPEC_1		0x2000	/* for FLG_{FLAGS, LIBPATH} */
#define	SEL_ACT_SPEC_2		0x4000	/* need special handling */

/*
 * Pattern match an LD_XXXX environment variable.  s1 points to the XXXX part
 * and len specifies its length (comparing a strings length before the string
 * itself speed things up).  s2 points to the token itself which has already
 * had any leading white-space removed.
 */
static void
ld_generic_env(const char *s1, size_t len, const char *s2, Word *lmflags,
    Word *lmtflags, uint_t env_flags, int aout)
{
	u_longlong_t	variable = 0;
	ushort_t	select = 0;
	const char	**str;
	Word		val = 0;

	/*
	 * Determine whether we're dealing with a replaceable or permanent
	 * string.
	 */
	if (env_flags & ENV_TYP_PERMANT) {
		/*
		 * If the string is from a configuration file and defined as
		 * permanent, assign it as permanent.
		 */
		select |= SEL_PERMANT;
	} else
		select |= SEL_REPLACE;

	/*
	 * Parse the variable given.
	 *
	 * The LD_AUDIT family.
	 */
	if (*s1 == 'A') {
		if ((len == MSG_LD_AUDIT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_AUDIT), MSG_LD_AUDIT_SIZE) == 0)) {
			/*
			 * Replaceable and permanent audit objects can exist.
			 */
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ? &rpl_audit : &prm_audit;
			variable = ENV_FLG_AUDIT;
		} else if ((len == MSG_LD_AUDIT_ARGS_SIZE) &&
		    (strncmp(s1, MSG_ORIG(MSG_LD_AUDIT_ARGS),
		    MSG_LD_AUDIT_ARGS_SIZE) == 0)) {
			/*
			 * A specialized variable for plt_exit() use, not
			 * documented for general use.
			 */
			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_AUDIT_ARGS;
		}
	}
	/*
	 * The LD_BIND family.
	 */
	else if (*s1 == 'B') {
		if ((len == MSG_LD_BIND_LAZY_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_BIND_LAZY),
		    MSG_LD_BIND_LAZY_SIZE) == 0)) {
			select |= SEL_ACT_RT2;
			val = RT_FL2_BINDLAZY;
			variable = ENV_FLG_BIND_LAZY;
		} else if ((len == MSG_LD_BIND_NOW_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_BIND_NOW), MSG_LD_BIND_NOW_SIZE) == 0)) {
			select |= SEL_ACT_RT2;
			val = RT_FL2_BINDNOW;
			variable = ENV_FLG_BIND_NOW;
		} else if ((len == MSG_LD_BIND_NOT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_BIND_NOT), MSG_LD_BIND_NOT_SIZE) == 0)) {
			/*
			 * Another trick, enabled to help debug AOUT
			 * applications under BCP, but not documented for
			 * general use.
			 */
			select |= SEL_ACT_RT;
			val = RT_FL_NOBIND;
			variable = ENV_FLG_BIND_NOT;
		} else if ((len == MSG_LD_BINDINGS_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_BINDINGS), MSG_LD_BINDINGS_SIZE) == 0)) {
			/*
			 * This variable is simply for backward compatibility.
			 * If this and LD_DEBUG are both specified, only one of
			 * the strings is going to get processed.
			 */
			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_BINDINGS;
		}
	}
	/*
	 * LD_CAP_FILES and LD_CONFIG family.
	 */
	else if (*s1 == 'C') {
		if ((len == MSG_LD_CAP_FILES_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_CAP_FILES), MSG_LD_CAP_FILES_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ?
			    &rpl_cap_files : &prm_cap_files;
			variable = ENV_FLG_CAP_FILES;
		} else if ((len == MSG_LD_CONFGEN_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_CONFGEN), MSG_LD_CONFGEN_SIZE) == 0)) {
			/*
			 * This variable is not documented for general use.
			 * Although originaly designed for internal use with
			 * crle(1), this variable is in use by the Studio
			 * auditing tools.  Hence, it can't be removed.
			 */
			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_CONFGEN;
		} else if ((len == MSG_LD_CONFIG_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_CONFIG), MSG_LD_CONFIG_SIZE) == 0)) {
			/*
			 * Secure applications must use a default configuration
			 * file.  A setting from a configuration file doesn't
			 * make sense (given we must be reading a configuration
			 * file to have gotten this).
			 */
			if ((rtld_flags & RT_FL_SECURE) ||
			    (env_flags & ENV_TYP_CONFIG))
				return;
			select |= SEL_ACT_STR;
			str = &config->c_name;
			variable = ENV_FLG_CONFIG;
		}
	}
	/*
	 * The LD_DEBUG family, LD_DEFERRED (internal, used by ldd(1)), and
	 * LD_DEMANGLE.
	 */
	else if (*s1 == 'D') {
		if ((len == MSG_LD_DEBUG_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_DEBUG), MSG_LD_DEBUG_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ? &rpl_debug : &prm_debug;
			variable = ENV_FLG_DEBUG;
		} else if ((len == MSG_LD_DEBUG_OUTPUT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_DEBUG_OUTPUT),
		    MSG_LD_DEBUG_OUTPUT_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = &dbg_file;
			variable = ENV_FLG_DEBUG_OUTPUT;
		} else if ((len == MSG_LD_DEFERRED_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_DEFERRED), MSG_LD_DEFERRED_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_DEFERRED;
			variable = ENV_FLG_DEFERRED;
		} else if ((len == MSG_LD_DEMANGLE_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_DEMANGLE), MSG_LD_DEMANGLE_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_DEMANGLE;
			variable = ENV_FLG_DEMANGLE;
		}
	}
	/*
	 * LD_FLAGS - collect the best variable definition.  On completion of
	 * environment variable processing pass the result to ld_flags_env()
	 * where they'll be decomposed and passed back to this routine.
	 */
	else if (*s1 == 'F') {
		if ((len == MSG_LD_FLAGS_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_FLAGS), MSG_LD_FLAGS_SIZE) == 0)) {
			select |= SEL_ACT_SPEC_1;
			str = &rpl_ldflags;
			variable = ENV_FLG_FLAGS;
		}
	}
	/*
	 * LD_HWCAP.
	 */
	else if (*s1 == 'H') {
		if ((len == MSG_LD_HWCAP_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_HWCAP), MSG_LD_HWCAP_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ?
			    &rpl_hwcap : &prm_hwcap;
			variable = ENV_FLG_HWCAP;
		}
	}
	/*
	 * LD_INIT (internal, used by ldd(1)).
	 */
	else if (*s1 == 'I') {
		if ((len == MSG_LD_INIT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_INIT), MSG_LD_INIT_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_INIT;
			variable = ENV_FLG_INIT;
		}
	}
	/*
	 * The LD_LIBRARY_PATH and LD_LOAD families.
	 */
	else if (*s1 == 'L') {
		if ((len == MSG_LD_LIBPATH_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_LIBPATH), MSG_LD_LIBPATH_SIZE) == 0)) {
			select |= SEL_ACT_SPEC_1;
			str = (select & SEL_REPLACE) ? &rpl_libpath :
			    &prm_libpath;
			variable = ENV_FLG_LIBPATH;
		} else if ((len == MSG_LD_LOADAVAIL_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_LOADAVAIL), MSG_LD_LOADAVAIL_SIZE) == 0)) {
			/*
			 * This variable is not documented for general use.
			 * Although originaly designed for internal use with
			 * crle(1), this variable is in use by the Studio
			 * auditing tools.  Hence, it can't be removed.
			 */
			select |= SEL_ACT_LML;
			val = LML_FLG_LOADAVAIL;
			variable = ENV_FLG_LOADAVAIL;
		} else if ((len == MSG_LD_LOADFLTR_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_LOADFLTR), MSG_LD_LOADFLTR_SIZE) == 0)) {
			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_LOADFLTR;
		}
	}
	/*
	 * LD_MACHCAP.
	 */
	else if (*s1 == 'M') {
		if ((len == MSG_LD_MACHCAP_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_MACHCAP), MSG_LD_MACHCAP_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ?
			    &rpl_machcap : &prm_machcap;
			variable = ENV_FLG_MACHCAP;
		}
	}
	/*
	 * The LD_NO family.
	 */
	else if (*s1 == 'N') {
		if ((len == MSG_LD_NOAUDIT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOAUDIT), MSG_LD_NOAUDIT_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOAUDIT;
			variable = ENV_FLG_NOAUDIT;
		} else if ((len == MSG_LD_NOAUXFLTR_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOAUXFLTR), MSG_LD_NOAUXFLTR_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOAUXFLTR;
			variable = ENV_FLG_NOAUXFLTR;
		} else if ((len == MSG_LD_NOBAPLT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOBAPLT), MSG_LD_NOBAPLT_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOBAPLT;
			variable = ENV_FLG_NOBAPLT;
		} else if ((len == MSG_LD_NOCONFIG_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOCONFIG), MSG_LD_NOCONFIG_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOCFG;
			variable = ENV_FLG_NOCONFIG;
		} else if ((len == MSG_LD_NODIRCONFIG_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NODIRCONFIG),
		    MSG_LD_NODIRCONFIG_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NODIRCFG;
			variable = ENV_FLG_NODIRCONFIG;
		} else if ((len == MSG_LD_NODIRECT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NODIRECT), MSG_LD_NODIRECT_SIZE) == 0)) {
			select |= SEL_ACT_LMLT;
			val = LML_TFLG_NODIRECT;
			variable = ENV_FLG_NODIRECT;
		} else if ((len == MSG_LD_NOENVCONFIG_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOENVCONFIG),
		    MSG_LD_NOENVCONFIG_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOENVCFG;
			variable = ENV_FLG_NOENVCONFIG;
		} else if ((len == MSG_LD_NOFLTCONFIG_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOFLTCONFIG),
		    MSG_LD_NOFLTCONFIG_SIZE) == 0)) {
			select |= SEL_ACT_RT2;
			val = RT_FL2_NOFLTCFG;
			variable = ENV_FLG_NOFLTCONFIG;
		} else if ((len == MSG_LD_NOLAZY_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOLAZY), MSG_LD_NOLAZY_SIZE) == 0)) {
			select |= SEL_ACT_LMLT;
			val = LML_TFLG_NOLAZYLD;
			variable = ENV_FLG_NOLAZY;
		} else if ((len == MSG_LD_NOOBJALTER_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOOBJALTER),
		    MSG_LD_NOOBJALTER_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOOBJALT;
			variable = ENV_FLG_NOOBJALTER;
		} else if ((len == MSG_LD_NOVERSION_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOVERSION), MSG_LD_NOVERSION_SIZE) == 0)) {
			select |= SEL_ACT_RT;
			val = RT_FL_NOVERSION;
			variable = ENV_FLG_NOVERSION;
		} else if ((len == MSG_LD_NOUNRESWEAK_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOUNRESWEAK),
		    MSG_LD_NOUNRESWEAK_SIZE) == 0)) {
			/*
			 * LD_NOUNRESWEAK (internal, used by ldd(1)).
			 */
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_NOUNRESWEAK;
			variable = ENV_FLG_NOUNRESWEAK;
		} else if ((len == MSG_LD_NOPAREXT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOPAREXT), MSG_LD_NOPAREXT_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_NOPAREXT;
			variable = ENV_FLG_NOPAREXT;
		} else if ((len == MSG_LD_NOENVIRON_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_NOENVIRON), MSG_LD_NOENVIRON_SIZE) == 0)) {
			/*
			 * LD_NOENVIRON can only be set with ld.so.1 -e.
			 */
			select |= SEL_ACT_RT;
			val = RT_FL_NOENVIRON;
			variable = ENV_FLG_NOENVIRON;
		}
	}
	/*
	 * LD_PLATCAP, LD_PRELOAD and LD_PROFILE family.
	 */
	else if (*s1 == 'P') {
		if ((len == MSG_LD_PLATCAP_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_PLATCAP), MSG_LD_PLATCAP_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ?
			    &rpl_platcap : &prm_platcap;
			variable = ENV_FLG_PLATCAP;
		} else if ((len == MSG_LD_PRELOAD_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_PRELOAD), MSG_LD_PRELOAD_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ? &rpl_preload :
			    &prm_preload;
			variable = ENV_FLG_PRELOAD;
		} else if ((len == MSG_LD_PROFILE_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_PROFILE), MSG_LD_PROFILE_SIZE) == 0)) {
			/*
			 * Only one user library can be profiled at a time.
			 */
			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_PROFILE;
		} else if ((len == MSG_LD_PROFILE_OUTPUT_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_PROFILE_OUTPUT),
		    MSG_LD_PROFILE_OUTPUT_SIZE) == 0)) {
			/*
			 * Only one user library can be profiled at a time.
			 */
			select |= SEL_ACT_STR;
			str = &profile_out;
			variable = ENV_FLG_PROFILE_OUTPUT;
		}
	}
	/*
	 * LD_SFCAP and LD_SIGNAL.
	 */
	else if (*s1 == 'S') {
		if ((len == MSG_LD_SFCAP_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_SFCAP), MSG_LD_SFCAP_SIZE) == 0)) {
			select |= SEL_ACT_STR;
			str = (select & SEL_REPLACE) ?
			    &rpl_sfcap : &prm_sfcap;
			variable = ENV_FLG_SFCAP;
		} else if ((len == MSG_LD_SIGNAL_SIZE) &&
		    (strncmp(s1, MSG_ORIG(MSG_LD_SIGNAL),
		    MSG_LD_SIGNAL_SIZE) == 0) &&
		    ((rtld_flags & RT_FL_SECURE) == 0)) {
			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_SIGNAL;
		}
	}
	/*
	 * The LD_TRACE family (internal, used by ldd(1)).  This definition is
	 * the key to enabling all other ldd(1) specific environment variables.
	 * In case an auditor is called, which in turn might exec(2) a
	 * subprocess, this variable is disabled, so that any subprocess
	 * escapes ldd(1) processing.
	 *
	 * Also, look for LD_TOXIC_PATH
	 */
	else if (*s1 == 'T') {
		if (((len == MSG_LD_TRACE_OBJS_SIZE) &&
		    (strncmp(s1, MSG_ORIG(MSG_LD_TRACE_OBJS),
		    MSG_LD_TRACE_OBJS_SIZE) == 0)) ||
		    ((len == MSG_LD_TRACE_OBJS_E_SIZE) &&
		    (((strncmp(s1, MSG_ORIG(MSG_LD_TRACE_OBJS_E),
		    MSG_LD_TRACE_OBJS_E_SIZE) == 0) && !aout) ||
		    ((strncmp(s1, MSG_ORIG(MSG_LD_TRACE_OBJS_A),
		    MSG_LD_TRACE_OBJS_A_SIZE) == 0) && aout)))) {
			char	*s0 = (char *)s1;

			select |= SEL_ACT_SPEC_2;
			variable = ENV_FLG_TRACE_OBJS;

#if	defined(__sparc) || defined(__x86)
			/*
			 * The simplest way to "disable" this variable is to
			 * truncate this string to "LD_'\0'". This string is
			 * ignored by any ld.so.1 environment processing.
			 * Use of such interfaces as unsetenv(3c) are overkill,
			 * and would drag too much libc implementation detail
			 * into ld.so.1.
			 */
			*s0 = '\0';
#else
/*
 * Verify that the above write is appropriate for any new platforms.
 */
#error	unsupported architecture!
#endif
		} else if ((len == MSG_LD_TRACE_PTHS_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_TRACE_PTHS),
		    MSG_LD_TRACE_PTHS_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_SEARCH;
			variable = ENV_FLG_TRACE_PTHS;
		} else if ((len == MSG_LD_TOXICPATH_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_TOXICPATH), MSG_LD_TOXICPATH_SIZE) == 0)) {
			select |= SEL_ACT_SPEC_1;
			str = &rpl_ldtoxic;
			variable = ENV_FLG_TOXICPATH;
		}

	}
	/*
	 * LD_UNREF and LD_UNUSED (internal, used by ldd(1)).
	 */
	else if (*s1 == 'U') {
		if ((len == MSG_LD_UNREF_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_UNREF), MSG_LD_UNREF_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_UNREF;
			variable = ENV_FLG_UNREF;
		} else if ((len == MSG_LD_UNUSED_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_UNUSED), MSG_LD_UNUSED_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_UNUSED;
			variable = ENV_FLG_UNUSED;
		}
	}
	/*
	 * LD_VERBOSE (internal, used by ldd(1)).
	 */
	else if (*s1 == 'V') {
		if ((len == MSG_LD_VERBOSE_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_VERBOSE), MSG_LD_VERBOSE_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_VERBOSE;
			variable = ENV_FLG_VERBOSE;
		}
	}
	/*
	 * LD_WARN (internal, used by ldd(1)).
	 */
	else if (*s1 == 'W') {
		if ((len == MSG_LD_WARN_SIZE) && (strncmp(s1,
		    MSG_ORIG(MSG_LD_WARN), MSG_LD_WARN_SIZE) == 0)) {
			select |= SEL_ACT_LML;
			val = LML_FLG_TRC_WARN;
			variable = ENV_FLG_WARN;
		}
	}

	if (variable == 0)
		return;

	/*
	 * If the variable is already processed with and ISA specific variable,
	 * no further processing is needed.
	 */
	if (((select & SEL_REPLACE) && (rplisa & variable)) ||
	    ((select & SEL_PERMANT) && (prmisa & variable)))
		return;

	/*
	 * If this variable has already been set via the command line, then
	 * ignore this variable.  The command line, -e, takes precedence.
	 */
	if (env_flags & ENV_TYP_ISA) {
		if (cmdisa & variable)
			return;
		if (env_flags & ENV_TYP_CMDLINE)
			cmdisa |= variable;
	} else {
		if (cmdgen & variable)
			return;
		if (env_flags & ENV_TYP_CMDLINE)
			cmdgen |= variable;
	}

	/*
	 * Mark the appropriate variables.
	 */
	if (env_flags & ENV_TYP_ISA) {
		/*
		 * This is an ISA setting.
		 */
		if (select & SEL_REPLACE) {
			if (rplisa & variable)
				return;
			rplisa |= variable;
		} else {
			prmisa |= variable;
		}
	} else {
		/*
		 * This is a non-ISA setting.
		 */
		if (select & SEL_REPLACE) {
			if (rplgen & variable)
				return;
			rplgen |= variable;
		} else
			prmgen |= variable;
	}

	/*
	 * Now perform the setting.
	 */
	if (select & SEL_ACT_RT) {
		if (s2)
			rtld_flags |= val;
		else
			rtld_flags &= ~val;
	} else if (select & SEL_ACT_RT2) {
		if (s2)
			rtld_flags2 |= val;
		else
			rtld_flags2 &= ~val;
	} else if (select & SEL_ACT_STR) {
		if (env_flags & ENV_TYP_NULL)
			*str = NULL;
		else
			*str = s2;
	} else if (select & SEL_ACT_LML) {
		if (s2)
			*lmflags |= val;
		else
			*lmflags &= ~val;
	} else if (select & SEL_ACT_LMLT) {
		if (s2)
			*lmtflags |= val;
		else
			*lmtflags &= ~val;
	} else if (select & SEL_ACT_SPEC_1) {
		/*
		 * variable is either ENV_FLG_FLAGS, ENV_FLG_LIBPATH, or
		 * ENV_FLG_TOXICPATH
		 */
		if (env_flags & ENV_TYP_NULL)
			*str = NULL;
		else
			*str = s2;
		if ((select & SEL_REPLACE) && (env_flags & ENV_TYP_CONFIG)) {
			if (s2) {
				if (variable == ENV_FLG_FLAGS)
					env_info |= ENV_INF_FLAGCFG;
				else
					env_info |= ENV_INF_PATHCFG;
			} else {
				if (variable == ENV_FLG_FLAGS)
					env_info &= ~ENV_INF_FLAGCFG;
				else
					env_info &= ~ENV_INF_PATHCFG;
			}
		}
	} else if (select & SEL_ACT_SPEC_2) {
		/*
		 * variables can be: ENV_FLG_
		 * 	AUDIT_ARGS, BINDING, CONFGEN, LOADFLTR, PROFILE,
		 *	SIGNAL, TRACE_OBJS
		 */
		switch (variable) {
		case ENV_FLG_AUDIT_ARGS:
			if (s2) {
				audit_argcnt = atoi(s2);
				audit_argcnt += audit_argcnt % 2;
			} else
				audit_argcnt = 0;
			break;
		case ENV_FLG_BINDINGS:
			if (s2)
				rpl_debug = MSG_ORIG(MSG_TKN_BINDINGS);
			else
				rpl_debug = NULL;
			break;
		case ENV_FLG_CONFGEN:
			if (s2) {
				rtld_flags |= RT_FL_CONFGEN;
				*lmflags |= LML_FLG_IGNRELERR;
			} else {
				rtld_flags &= ~RT_FL_CONFGEN;
				*lmflags &= ~LML_FLG_IGNRELERR;
			}
			break;
		case ENV_FLG_LOADFLTR:
			if (s2) {
				*lmtflags |= LML_TFLG_LOADFLTR;
				if (*s2 == '2')
					rtld_flags |= RT_FL_WARNFLTR;
			} else {
				*lmtflags &= ~LML_TFLG_LOADFLTR;
				rtld_flags &= ~RT_FL_WARNFLTR;
			}
			break;
		case ENV_FLG_PROFILE:
			profile_name = s2;
			if (s2) {
				if (strcmp(s2, MSG_ORIG(MSG_FIL_RTLD)) == 0) {
					return;
				}
				/* BEGIN CSTYLED */
				if (rtld_flags & RT_FL_SECURE) {
					profile_lib =
#if	defined(_ELF64)
					    MSG_ORIG(MSG_PTH_LDPROFSE_64);
#else
					    MSG_ORIG(MSG_PTH_LDPROFSE);
#endif
				} else {
					profile_lib =
#if	defined(_ELF64)
					    MSG_ORIG(MSG_PTH_LDPROF_64);
#else
					    MSG_ORIG(MSG_PTH_LDPROF);
#endif
				}
				/* END CSTYLED */
			} else
				profile_lib = NULL;
			break;
		case ENV_FLG_SIGNAL:
			killsig = s2 ? atoi(s2) : SIGKILL;
			break;
		case ENV_FLG_TRACE_OBJS:
			if (s2) {
				*lmflags |= LML_FLG_TRC_ENABLE;
				if (*s2 == '2')
					*lmflags |= LML_FLG_TRC_LDDSTUB;
			} else
				*lmflags &=
				    ~(LML_FLG_TRC_ENABLE | LML_FLG_TRC_LDDSTUB);
			break;
		}
	}
}

/*
 * Determine whether we have an architecture specific environment variable.
 * If we do, and we're the wrong architecture, it'll just get ignored.
 * Otherwise the variable is processed in it's architecture neutral form.
 */
static int
ld_arch_env(const char *s1, size_t *len)
{
	size_t	_len = *len - 3;

	if (s1[_len++] == '_') {
		if ((s1[_len] == '3') && (s1[_len + 1] == '2')) {
#if	defined(_ELF64)
			return (ENV_TYP_IGNORE);
#else
			*len = *len - 3;
			return (ENV_TYP_ISA);
#endif
		}
		if ((s1[_len] == '6') && (s1[_len + 1] == '4')) {
#if	defined(_ELF64)
			*len = *len - 3;
			return (ENV_TYP_ISA);
#else
			return (ENV_TYP_IGNORE);
#endif
		}
	}
	return (0);
}

/*
 * Process an LD_FLAGS environment variable.  The value can be a comma
 * separated set of tokens, which are sent (in upper case) into the generic
 * LD_XXXX environment variable engine.  For example:
 *
 *	LD_FLAGS=bind_now=		->	LD_BIND_NOW=
 *	LD_FLAGS=bind_now		->	LD_BIND_NOW=1
 *	LD_FLAGS=library_path=		->	LD_LIBRARY_PATH=
 *	LD_FLAGS=library_path=/foo:.	->	LD_LIBRARY_PATH=/foo:.
 *	LD_FLAGS=debug=files:detail	->	LD_DEBUG=files:detail
 * or
 *	LD_FLAGS=bind_now,library_path=/foo:.,debug=files:detail
 */
static int
ld_flags_env(const char *str, Word *lmflags, Word *lmtflags,
    uint_t env_flags, int aout)
{
	char	*nstr, *sstr, *estr = NULL;
	size_t	nlen, len;

	if (str == NULL)
		return (0);

	/*
	 * Create a new string as we're going to transform the token(s) into
	 * uppercase and separate tokens with nulls.
	 */
	len = strlen(str);
	if ((nstr = malloc(len + 1)) == NULL)
		return (1);
	(void) strcpy(nstr, str);

	for (sstr = nstr; sstr; sstr++, len--) {
		int	flags = 0;

		if ((*sstr != '\0') && (*sstr != ',')) {
			if (estr == NULL) {
				if (*sstr == '=')
					estr = sstr;
				else {
					/*
					 * Translate token to uppercase.  Don't
					 * use toupper(3C) as including this
					 * code doubles the size of ld.so.1.
					 */
					if ((*sstr >= 'a') && (*sstr <= 'z'))
						*sstr = *sstr - ('a' - 'A');
				}
			}
			continue;
		}

		*sstr = '\0';

		/*
		 * Have we discovered an "=" string.
		 */
		if (estr) {
			nlen = estr - nstr;

			/*
			 * If this is an unqualified "=", then this variable
			 * is intended to ensure a feature is disabled.
			 */
			if ((*++estr == '\0') || (*estr == ','))
				estr = NULL;
		} else {
			nlen = sstr - nstr;

			/*
			 * If there is no "=" found, fabricate a boolean
			 * definition for any unqualified variable.  Thus,
			 * LD_FLAGS=bind_now is represented as BIND_NOW=1.
			 * The value "1" is sufficient to assert any boolean
			 * variables.  Setting of ENV_TYP_NULL ensures any
			 * string usage is reset to a NULL string, thus
			 * LD_FLAGS=library_path is equivalent to
			 * LIBRARY_PATH='\0'.
			 */
			flags |= ENV_TYP_NULL;
			estr = (char *)MSG_ORIG(MSG_STR_ONE);
		}

		/*
		 * Determine whether the environment variable is 32- or 64-bit
		 * specific.  The length, len, will reflect the architecture
		 * neutral portion of the string.
		 */
		if ((flags |= ld_arch_env(nstr, &nlen)) != ENV_TYP_IGNORE) {
			ld_generic_env(nstr, nlen, estr, lmflags,
			    lmtflags, (env_flags | flags), aout);
		}
		if (len == 0)
			break;

		nstr = sstr + 1;
		estr = NULL;
	}

	return (0);
}

/*
 * Variant of getopt(), intended for use when ld.so.1 is invoked directly
 * from the command line.  The only command line option allowed is -e followed
 * by a runtime linker environment variable.
 */
int
rtld_getopt(char **argv, char ***envp, auxv_t **auxv, Word *lmflags,
    Word *lmtflags, int aout)
{
	int	ndx;

	for (ndx = 1; argv[ndx]; ndx++) {
		char	*str;

		if (argv[ndx][0] != '-')
			break;

		if (argv[ndx][1] == '\0') {
			ndx++;
			break;
		}

		if (argv[ndx][1] != 'e')
			return (1);

		if (argv[ndx][2] == '\0') {
			ndx++;
			if (argv[ndx] == NULL)
				return (1);
			str = argv[ndx];
		} else
			str = &argv[ndx][2];

		/*
		 * If the environment variable starts with LD_, strip the LD_.
		 * Otherwise, take things as is.  Indicate that this variable
		 * originates from the command line, as these variables take
		 * precedence over any environment variables, or configuration
		 * file variables.
		 */
		if ((str[0] == 'L') && (str[1] == 'D') && (str[2] == '_') &&
		    (str[3] != '\0'))
			str += 3;
		if (ld_flags_env(str, lmflags, lmtflags,
		    ENV_TYP_CMDLINE, aout) == 1)
			return (1);
	}

	/*
	 * Make sure an object file has been specified.
	 */
	if (argv[ndx] == NULL)
		return (1);

	/*
	 * Having gotten the arguments, clean ourselves off of the stack.
	 * This results in a process that looks as if it was executed directly
	 * from the application.
	 */
	stack_cleanup(argv, envp, auxv, ndx);
	return (0);
}

/*
 * Process a single LD_XXXX string.
 */
static void
ld_str_env(const char *s1, Word *lmflags, Word *lmtflags, uint_t env_flags,
    int aout)
{
	const char	*s2;
	size_t		len;
	int		flags;

	/*
	 * In a branded process we must ignore all LD_XXXX variables because
	 * they are intended for the brand's linker.  To affect the native
	 * linker, use LD_BRAND_XXXX instead.
	 */
	if (rtld_flags2 & RT_FL2_BRANDED) {
		if (strncmp(s1, MSG_ORIG(MSG_LD_BRAND_PREFIX),
		    MSG_LD_BRAND_PREFIX_SIZE) != 0)
			return;
		s1 += MSG_LD_BRAND_PREFIX_SIZE;
	}

	/*
	 * Variables with no value (ie. LD_XXXX=) turn a capability off.
	 */
	if ((s2 = strchr(s1, '=')) == NULL) {
		len = strlen(s1);
		s2 = NULL;
	} else if (*++s2 == '\0') {
		len = strlen(s1) - 1;
		s2 = NULL;
	} else {
		len = s2 - s1 - 1;
		while (conv_strproc_isspace(*s2))
			s2++;
	}

	/*
	 * Determine whether the environment variable is 32-bit or 64-bit
	 * specific.  The length, len, will reflect the architecture neutral
	 * portion of the string.
	 */
	if ((flags = ld_arch_env(s1, &len)) == ENV_TYP_IGNORE)
		return;
	env_flags |= flags;

	ld_generic_env(s1, len, s2, lmflags, lmtflags, env_flags, aout);
}

/*
 * Internal getenv routine.  Called immediately after ld.so.1 initializes
 * itself to process any locale specific environment variables, and collect
 * any LD_XXXX variables for later processing.
 */
#define	LOC_LANG	1
#define	LOC_MESG	2
#define	LOC_ALL		3

int
readenv_user(const char **envp, APlist **ealpp)
{
	char		*locale;
	const char	*s1;
	int		loc = 0;

	for (s1 = *envp; s1; envp++, s1 = *envp) {
		const char	*s2;

		if (*s1++ != 'L')
			continue;

		/*
		 * See if we have any locale environment settings.  These
		 * environment variables have a precedence, LC_ALL is higher
		 * than LC_MESSAGES which is higher than LANG.
		 */
		s2 = s1;
		if ((*s2++ == 'C') && (*s2++ == '_') && (*s2 != '\0')) {
			if (strncmp(s2, MSG_ORIG(MSG_LC_ALL),
			    MSG_LC_ALL_SIZE) == 0) {
				s2 += MSG_LC_ALL_SIZE;
				if ((*s2 != '\0') && (loc < LOC_ALL)) {
					glcs[CI_LCMESSAGES].lc_un.lc_ptr =
					    (char *)s2;
					loc = LOC_ALL;
				}
			} else if (strncmp(s2, MSG_ORIG(MSG_LC_MESSAGES),
			    MSG_LC_MESSAGES_SIZE) == 0) {
				s2 += MSG_LC_MESSAGES_SIZE;
				if ((*s2 != '\0') && (loc < LOC_MESG)) {
					glcs[CI_LCMESSAGES].lc_un.lc_ptr =
					    (char *)s2;
					loc = LOC_MESG;
				}
			}
			continue;
		}

		s2 = s1;
		if ((*s2++ == 'A') && (*s2++ == 'N') && (*s2++ == 'G') &&
		    (*s2++ == '=') && (*s2 != '\0') && (loc < LOC_LANG)) {
			glcs[CI_LCMESSAGES].lc_un.lc_ptr = (char *)s2;
			loc = LOC_LANG;
			continue;
		}

		/*
		 * Pick off any LD_XXXX environment variables.
		 */
		if ((*s1++ == 'D') && (*s1++ == '_') && (*s1 != '\0')) {
			if (aplist_append(ealpp, s1, AL_CNT_ENVIRON) == NULL)
				return (1);
		}
	}

	/*
	 * If we have a locale setting make sure it's worth processing further.
	 * C and POSIX locales don't need any processing.  In addition, to
	 * ensure no one escapes the /usr/lib/locale hierarchy, don't allow
	 * the locale to contain a segment that leads upward in the file system
	 * hierarchy (i.e. no '..' segments).   Given that we'll be confined to
	 * the /usr/lib/locale hierarchy, there is no need to extensively
	 * validate the mode or ownership of any message file (as libc's
	 * generic handling of message files does), or be concerned with
	 * symbolic links that might otherwise send us elsewhere.  Duplicate
	 * the string so that new locale setting can generically cleanup any
	 * previous locales.
	 */
	if ((locale = glcs[CI_LCMESSAGES].lc_un.lc_ptr) != NULL) {
		if (((*locale == 'C') && (*(locale + 1) == '\0')) ||
		    (strcmp(locale, MSG_ORIG(MSG_TKN_POSIX)) == 0) ||
		    (strstr(locale, MSG_ORIG(MSG_TKN_DOTDOT)) != NULL))
			glcs[CI_LCMESSAGES].lc_un.lc_ptr = NULL;
		else
			glcs[CI_LCMESSAGES].lc_un.lc_ptr = strdup(locale);
	}
	return (0);
}

/*
 * Process any LD_XXXX environment variables collected by readenv_user().
 */
int
procenv_user(APlist *ealp, Word *lmflags, Word *lmtflags, int aout)
{
	Aliste		idx;
	const char	*s1;

	for (APLIST_TRAVERSE(ealp, idx, s1))
		ld_str_env(s1, lmflags, lmtflags, 0, aout);

	/*
	 * Having collected the best representation of any LD_FLAGS, process
	 * these strings.
	 */
	if (rpl_ldflags) {
		if (ld_flags_env(rpl_ldflags, lmflags, lmtflags, 0, aout) == 1)
			return (1);
		rpl_ldflags = NULL;
	}

	/*
	 * Don't allow environment controlled auditing when tracing or if
	 * explicitly disabled.  Trigger all tracing modes from
	 * LML_FLG_TRC_ENABLE.
	 */
	if ((*lmflags & LML_FLG_TRC_ENABLE) || (rtld_flags & RT_FL_NOAUDIT))
		rpl_audit = profile_lib = profile_name = NULL;
	if ((*lmflags & LML_FLG_TRC_ENABLE) == 0)
		*lmflags &= ~LML_MSK_TRC;

	/*
	 * If both LD_BIND_NOW and LD_BIND_LAZY are specified, the former wins.
	 */
	if ((rtld_flags2 & (RT_FL2_BINDNOW | RT_FL2_BINDLAZY)) ==
	    (RT_FL2_BINDNOW | RT_FL2_BINDLAZY))
		rtld_flags2 &= ~RT_FL2_BINDLAZY;

	/*
	 * When using ldd(1) -r or -d against an executable, assert -p.
	 */
	if ((*lmflags &
	    (LML_FLG_TRC_WARN | LML_FLG_TRC_LDDSTUB)) == LML_FLG_TRC_WARN)
		*lmflags |= LML_FLG_TRC_NOPAREXT;

	return (0);
}

/*
 * Configuration environment processing.  Called after the a.out has been
 * processed (as the a.out can specify its own configuration file).
 */
int
readenv_config(Rtc_env * envtbl, Addr addr, int aout)
{
	Word		*lmflags = &(lml_main.lm_flags);
	Word		*lmtflags = &(lml_main.lm_tflags);

	if (envtbl == NULL)
		return (0);

	while (envtbl->env_str) {
		uint_t		env_flags = ENV_TYP_CONFIG;
		const char	*s1 = (const char *)(envtbl->env_str + addr);

		if (envtbl->env_flags & RTC_ENV_PERMANT)
			env_flags |= ENV_TYP_PERMANT;

		if ((*s1++ == 'L') && (*s1++ == 'D') &&
		    (*s1++ == '_') && (*s1 != '\0'))
			ld_str_env(s1, lmflags, lmtflags, env_flags, 0);

		envtbl++;
	}

	/*
	 * Having collected the best representation of any LD_FLAGS, process
	 * these strings.
	 */
	if (ld_flags_env(rpl_ldflags, lmflags, lmtflags, 0, aout) == 1)
		return (1);
	if (ld_flags_env(prm_ldflags, lmflags, lmtflags, ENV_TYP_CONFIG,
	    aout) == 1)
		return (1);

	/*
	 * Don't allow environment controlled auditing when tracing or if
	 * explicitly disabled.  Trigger all tracing modes from
	 * LML_FLG_TRC_ENABLE.
	 */
	if ((*lmflags & LML_FLG_TRC_ENABLE) || (rtld_flags & RT_FL_NOAUDIT))
		prm_audit = profile_lib = profile_name = NULL;
	if ((*lmflags & LML_FLG_TRC_ENABLE) == 0)
		*lmflags &= ~LML_MSK_TRC;

	return (0);
}

int
dowrite(Prfbuf * prf)
{
	/*
	 * We do not have a valid file descriptor, so we are unable
	 * to flush the buffer.
	 */
	if (prf->pr_fd == -1)
		return (0);
	(void) write(prf->pr_fd, prf->pr_buf, prf->pr_cur - prf->pr_buf);
	prf->pr_cur = prf->pr_buf;
	return (1);
}

/*
 * Simplified printing.  The following conversion specifications are supported:
 *
 *	% [#] [-] [min field width] [. precision] s|d|x|c
 *
 *
 * dorprf takes the output buffer in the form of Prfbuf which permits
 * the verification of the output buffer size and the concatenation
 * of data to an already existing output buffer.  The Prfbuf
 * structure contains the following:
 *
 *  pr_buf	pointer to the beginning of the output buffer.
 *  pr_cur	pointer to the next available byte in the output buffer.  By
 *		setting pr_cur ahead of pr_buf you can append to an already
 *		existing buffer.
 *  pr_len	the size of the output buffer.  By setting pr_len to '0' you
 *		disable protection from overflows in the output buffer.
 *  pr_fd	a pointer to the file-descriptor the buffer will eventually be
 *		output to.  If pr_fd is set to '-1' then it's assumed there is
 *		no output buffer, and doprf() will return with an error to
 *		indicate an output buffer overflow.  If pr_fd is > -1 then when
 *		the output buffer is filled it will be flushed to pr_fd and will
 *		then be	available for additional data.
 */
#define	FLG_UT_MINUS	0x0001	/* - */
#define	FLG_UT_SHARP	0x0002	/* # */
#define	FLG_UT_DOTSEEN	0x0008	/* dot appeared in format spec */

/*
 * This macro is for use from within doprf only.  It is to be used for checking
 * the output buffer size and placing characters into the buffer.
 */
#define	PUTC(c) \
	{ \
		char tmpc; \
		\
		tmpc = (c); \
		if (bufsiz && (bp >= bufend)) { \
			prf->pr_cur = bp; \
			if (dowrite(prf) == 0) \
				return (0); \
			bp = prf->pr_cur; \
		} \
		*bp++ = tmpc; \
	}

/*
 * Define a local buffer size for building a numeric value - large enough to
 * hold a 64-bit value.
 */
#define	NUM_SIZE	22

size_t
doprf(const char *format, va_list args, Prfbuf *prf)
{
	char	c;
	char	*bp = prf->pr_cur;
	char	*bufend = prf->pr_buf + prf->pr_len;
	size_t	bufsiz = prf->pr_len;

	while ((c = *format++) != '\0') {
		if (c != '%') {
			PUTC(c);
		} else {
			int	base = 0, flag = 0, width = 0, prec = 0;
			size_t	_i;
			int	_c, _n;
			char	*_s;
			int	ls = 0;
again:
			c = *format++;
			switch (c) {
			case '-':
				flag |= FLG_UT_MINUS;
				goto again;
			case '#':
				flag |= FLG_UT_SHARP;
				goto again;
			case '.':
				flag |= FLG_UT_DOTSEEN;
				goto again;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				if (flag & FLG_UT_DOTSEEN)
					prec = (prec * 10) + c - '0';
				else
					width = (width * 10) + c - '0';
				goto again;
			case 'x':
			case 'X':
				base = 16;
				break;
			case 'd':
			case 'D':
			case 'u':
				base = 10;
				flag &= ~FLG_UT_SHARP;
				break;
			case 'l':
				base = 10;
				ls++; /* number of l's (long or long long) */
				if ((*format == 'l') ||
				    (*format == 'd') || (*format == 'D') ||
				    (*format == 'x') || (*format == 'X') ||
				    (*format == 'o') || (*format == 'O') ||
				    (*format == 'u') || (*format == 'U'))
					goto again;
				break;
			case 'o':
			case 'O':
				base = 8;
				break;
			case 'c':
				_c = va_arg(args, int);

				for (_i = 24; _i > 0; _i -= 8) {
					if ((c = ((_c >> _i) & 0x7f)) != 0) {
						PUTC(c);
					}
				}
				if ((c = ((_c >> _i) & 0x7f)) != 0) {
					PUTC(c);
				}
				break;
			case 's':
				_s = va_arg(args, char *);
				_i = strlen(_s);
				/* LINTED */
				_n = (int)(width - _i);
				if (!prec)
					/* LINTED */
					prec = (int)_i;

				if (width && !(flag & FLG_UT_MINUS)) {
					while (_n-- > 0)
						PUTC(' ');
				}
				while (((c = *_s++) != 0) && prec--) {
					PUTC(c);
				}
				if (width && (flag & FLG_UT_MINUS)) {
					while (_n-- > 0)
						PUTC(' ');
				}
				break;
			case '%':
				PUTC('%');
				break;
			default:
				break;
			}

			/*
			 * Numeric processing
			 */
			if (base) {
				char		local[NUM_SIZE];
				size_t		ssize = 0, psize = 0;
				const char	*string =
				    MSG_ORIG(MSG_STR_HEXNUM);
				const char	*prefix =
				    MSG_ORIG(MSG_STR_EMPTY);
				u_longlong_t	num;

				switch (ls) {
				case 0:	/* int */
					num = (u_longlong_t)
					    va_arg(args, uint_t);
					break;
				case 1:	/* long */
					num = (u_longlong_t)
					    va_arg(args, ulong_t);
					break;
				case 2:	/* long long */
					num = va_arg(args, u_longlong_t);
					break;
				}

				if (flag & FLG_UT_SHARP) {
					if (base == 16) {
						prefix = MSG_ORIG(MSG_STR_HEX);
						psize = 2;
					} else {
						prefix = MSG_ORIG(MSG_STR_ZERO);
						psize = 1;
					}
				}
				if ((base == 10) && (long)num < 0) {
					prefix = MSG_ORIG(MSG_STR_NEGATE);
					psize = MSG_STR_NEGATE_SIZE;
					num = (u_longlong_t)(-(longlong_t)num);
				}

				/*
				 * Convert the numeric value into a local
				 * string (stored in reverse order).
				 */
				_s = local;
				do {
					*_s++ = string[num % base];
					num /= base;
					ssize++;
				} while (num);

				ASSERT(ssize < sizeof (local));

				/*
				 * Provide any precision or width padding.
				 */
				if (prec) {
					/* LINTED */
					_n = (int)(prec - ssize);
					while ((_n-- > 0) &&
					    (ssize < sizeof (local))) {
						*_s++ = '0';
						ssize++;
					}
				}
				if (width && !(flag & FLG_UT_MINUS)) {
					/* LINTED */
					_n = (int)(width - ssize - psize);
					while (_n-- > 0) {
						PUTC(' ');
					}
				}

				/*
				 * Print any prefix and the numeric string
				 */
				while (*prefix)
					PUTC(*prefix++);
				do {
					PUTC(*--_s);
				} while (_s > local);

				/*
				 * Provide any width padding.
				 */
				if (width && (flag & FLG_UT_MINUS)) {
					/* LINTED */
					_n = (int)(width - ssize - psize);
					while (_n-- > 0)
						PUTC(' ');
				}
			}
		}
	}

	PUTC('\0');
	prf->pr_cur = bp;
	return (1);
}

static int
doprintf(const char *format, va_list args, Prfbuf *prf)
{
	char	*ocur = prf->pr_cur;

	if (doprf(format, args, prf) == 0)
		return (0);
	/* LINTED */
	return ((int)(prf->pr_cur - ocur));
}

/* VARARGS2 */
int
sprintf(char *buf, const char *format, ...)
{
	va_list	args;
	int	len;
	Prfbuf	prf;

	va_start(args, format);
	prf.pr_buf = prf.pr_cur = buf;
	prf.pr_len = 0;
	prf.pr_fd = -1;
	len = doprintf(format, args, &prf);
	va_end(args);

	/*
	 * sprintf() return value excludes the terminating null byte.
	 */
	return (len - 1);
}

/* VARARGS3 */
int
snprintf(char *buf, size_t n, const char *format, ...)
{
	va_list	args;
	int	len;
	Prfbuf	prf;

	va_start(args, format);
	prf.pr_buf = prf.pr_cur = buf;
	prf.pr_len = n;
	prf.pr_fd = -1;
	len = doprintf(format, args, &prf);
	va_end(args);

	return (len);
}

/* VARARGS2 */
int
bufprint(Prfbuf *prf, const char *format, ...)
{
	va_list	args;
	int	len;

	va_start(args, format);
	len = doprintf(format, args, prf);
	va_end(args);

	return (len);
}

/*PRINTFLIKE1*/
int
printf(const char *format, ...)
{
	va_list	args;
	char 	buffer[ERRSIZE];
	Prfbuf	prf;

	va_start(args, format);
	prf.pr_buf = prf.pr_cur = buffer;
	prf.pr_len = ERRSIZE;
	prf.pr_fd = 1;
	(void) doprf(format, args, &prf);
	va_end(args);
	/*
	 * Trim trailing '\0' form buffer
	 */
	prf.pr_cur--;
	return (dowrite(&prf));
}

static char	errbuf[ERRSIZE], *nextptr = errbuf, *prevptr = NULL;

/*
 * All error messages go through eprintf().  During process initialization,
 * these messages are directed to the standard error, however once control has
 * been passed to the applications code these messages are stored in an internal
 * buffer for use with dlerror().  Note, fatal error conditions that may occur
 * while running the application will still cause a standard error message, see
 * rtldexit() in this file for details.
 * The RT_FL_APPLIC flag serves to indicate the transition between process
 * initialization and when the applications code is running.
 */
void
veprintf(Lm_list *lml, Error error, const char *format, va_list args)
{
	int		overflow = 0;
	static int	lock = 0;
	Prfbuf		prf;

	if (lock || (nextptr == (errbuf + ERRSIZE)))
		return;

	/*
	 * Note: this lock is here to prevent the same thread from recursively
	 * entering itself during a eprintf.  ie: during eprintf malloc() fails
	 * and we try and call eprintf ... and then malloc() fails ....
	 */
	lock = 1;

	/*
	 * If we have completed startup initialization, all error messages
	 * must be saved.  These are reported through dlerror().  If we're
	 * still in the initialization stage, output the error directly and
	 * add a newline.
	 */
	prf.pr_buf = prf.pr_cur = nextptr;
	prf.pr_len = ERRSIZE - (nextptr - errbuf);

	if ((rtld_flags & RT_FL_APPLIC) == 0)
		prf.pr_fd = 2;
	else
		prf.pr_fd = -1;

	if (error > ERR_NONE) {
		if ((error == ERR_FATAL) && (rtld_flags2 & RT_FL2_FTL2WARN))
			error = ERR_WARNING;
		switch (error) {
		case ERR_WARNING_NF:
			if (err_strs[ERR_WARNING_NF] == NULL)
				err_strs[ERR_WARNING_NF] =
				    MSG_INTL(MSG_ERR_WARNING);
			break;
		case ERR_WARNING:
			if (err_strs[ERR_WARNING] == NULL)
				err_strs[ERR_WARNING] =
				    MSG_INTL(MSG_ERR_WARNING);
			break;
		case ERR_GUIDANCE:
			if (err_strs[ERR_GUIDANCE] == NULL)
				err_strs[ERR_GUIDANCE] =
				    MSG_INTL(MSG_ERR_GUIDANCE);
			break;
		case ERR_FATAL:
			if (err_strs[ERR_FATAL] == NULL)
				err_strs[ERR_FATAL] = MSG_INTL(MSG_ERR_FATAL);
			break;
		case ERR_ELF:
			if (err_strs[ERR_ELF] == NULL)
				err_strs[ERR_ELF] = MSG_INTL(MSG_ERR_ELF);
			break;
		}
		if (procname) {
			if (bufprint(&prf, MSG_ORIG(MSG_STR_EMSGFOR1),
			    rtldname, procname, err_strs[error]) == 0)
				overflow = 1;
		} else {
			if (bufprint(&prf, MSG_ORIG(MSG_STR_EMSGFOR2),
			    rtldname, err_strs[error]) == 0)
				overflow = 1;
		}
		if (overflow == 0) {
			/*
			 * Remove the terminating '\0'.
			 */
			prf.pr_cur--;
		}
	}

	if ((overflow == 0) && doprf(format, args, &prf) == 0)
		overflow = 1;

	/*
	 * If this is an ELF error, it will have been generated by a support
	 * object that has a dependency on libelf.  ld.so.1 doesn't generate any
	 * ELF error messages as it doesn't interact with libelf.  Determine the
	 * ELF error string.
	 */
	if ((overflow == 0) && (error == ERR_ELF)) {
		static int		(*elfeno)() = 0;
		static const char	*(*elfemg)();
		const char		*emsg;
		Rt_map			*dlmp, *lmp = lml_rtld.lm_head;

		if (NEXT(lmp) && (elfeno == 0)) {
			if (((elfemg = (const char *(*)())dlsym_intn(RTLD_NEXT,
			    MSG_ORIG(MSG_SYM_ELFERRMSG),
			    lmp, &dlmp)) == NULL) ||
			    ((elfeno = (int (*)())dlsym_intn(RTLD_NEXT,
			    MSG_ORIG(MSG_SYM_ELFERRNO), lmp, &dlmp)) == NULL))
				elfeno = 0;
		}

		/*
		 * Lookup the message; equivalent to elf_errmsg(elf_errno()).
		 */
		if (elfeno && ((emsg = (* elfemg)((* elfeno)())) != NULL)) {
			prf.pr_cur--;
			if (bufprint(&prf, MSG_ORIG(MSG_STR_EMSGFOR2),
			    emsg) == 0)
				overflow = 1;
		}
	}

	/*
	 * Push out any message that's been built.  Note, in the case of an
	 * overflow condition, this message may be incomplete, in which case
	 * make sure any partial string is null terminated.
	 */
	if ((rtld_flags & (RT_FL_APPLIC | RT_FL_SILENCERR)) == 0) {
		*(prf.pr_cur - 1) = '\n';
		(void) dowrite(&prf);
	}
	if (overflow)
		*(prf.pr_cur - 1) = '\0';

	DBG_CALL(Dbg_util_str(lml, nextptr));

	/*
	 * Determine if there was insufficient space left in the buffer to
	 * complete the message.  If so, we'll have printed out as much as had
	 * been processed if we're not yet executing the application.
	 * Otherwise, there will be some debugging diagnostic indicating
	 * as much of the error message as possible.  Write out a final buffer
	 * overflow diagnostic - unlocalized, so we don't chance more errors.
	 */
	if (overflow) {
		char	*str = (char *)MSG_INTL(MSG_EMG_BUFOVRFLW);

		if ((rtld_flags & RT_FL_SILENCERR) == 0) {
			lasterr = str;

			if ((rtld_flags & RT_FL_APPLIC) == 0) {
				(void) write(2, str, strlen(str));
				(void) write(2, MSG_ORIG(MSG_STR_NL),
				    MSG_STR_NL_SIZE);
			}
		}
		DBG_CALL(Dbg_util_str(lml, str));

		lock = 0;
		nextptr = errbuf + ERRSIZE;
		return;
	}

	/*
	 * If the application has started, then error messages are being saved
	 * for retrieval by dlerror(), or possible flushing from rtldexit() in
	 * the case of a fatal error.  In this case, establish the next error
	 * pointer.  If we haven't started the application, the whole message
	 * buffer can be reused.
	 */
	if ((rtld_flags & RT_FL_SILENCERR) == 0) {
		lasterr = nextptr;

		/*
		 * Note, should we encounter an error such as ENOMEM, there may
		 * be a number of the same error messages (ie. an operation
		 * fails with ENOMEM, and then the attempts to construct the
		 * error message itself, which incurs additional ENOMEM errors).
		 * Compare any previous error message with the one we've just
		 * created to prevent any duplication clutter.
		 */
		if ((rtld_flags & RT_FL_APPLIC) &&
		    ((prevptr == NULL) || (strcmp(prevptr, nextptr) != 0))) {
			prevptr = nextptr;
			nextptr = prf.pr_cur;
			*nextptr = '\0';
		}
	}
	lock = 0;
}

/*PRINTFLIKE3*/
void
eprintf(Lm_list *lml, Error error, const char *format, ...)
{
	va_list		args;

	va_start(args, format);
	veprintf(lml, error, format, args);
	va_end(args);
}

#if	DEBUG
/*
 * Provide assfail() for ASSERT() statements.  See <sys/debug.h> for further
 * details.
 */
int
assfail(const char *a, const char *f, int l)
{
	(void) printf("assertion failed: %s, file: %s, line: %d\n", a, f, l);
	(void) _lwp_kill(_lwp_self(), SIGABRT);
	return (0);
}
#endif

/*
 * Exit.  If we arrive here with a non zero status it's because of a fatal
 * error condition (most commonly a relocation error).  If the application has
 * already had control, then the actual fatal error message will have been
 * recorded in the dlerror() message buffer.  Print the message before really
 * exiting.
 */
void
rtldexit(Lm_list * lml, int status)
{
	if (status) {
		if (rtld_flags & RT_FL_APPLIC) {
			/*
			 * If the error buffer has been used, write out all
			 * pending messages - lasterr is simply a pointer to
			 * the last message in this buffer.  However, if the
			 * buffer couldn't be created at all, lasterr points
			 * to a constant error message string.
			 */
			if (*errbuf) {
				char	*errptr = errbuf;
				char	*errend = errbuf + ERRSIZE;

				while ((errptr < errend) && *errptr) {
					size_t	size = strlen(errptr);
					(void) write(2, errptr, size);
					(void) write(2, MSG_ORIG(MSG_STR_NL),
					    MSG_STR_NL_SIZE);
					errptr += (size + 1);
				}
			}
			if (lasterr && ((lasterr < errbuf) ||
			    (lasterr > (errbuf + ERRSIZE)))) {
				(void) write(2, lasterr, strlen(lasterr));
				(void) write(2, MSG_ORIG(MSG_STR_NL),
				    MSG_STR_NL_SIZE);
			}
		}
		leave(lml, 0);
		(void) _lwp_kill(_lwp_self(), killsig);
	}
	_exit(status);
}

/*
 * Map anonymous memory via MAP_ANON (added in Solaris 8).
 */
void *
dz_map(Lm_list *lml, caddr_t addr, size_t len, int prot, int flags)
{
	caddr_t	va;

	if ((va = (caddr_t)mmap(addr, len, prot,
	    (flags | MAP_ANON), -1, 0)) == MAP_FAILED) {
		int	err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_MMAPANON),
		    strerror(err));
		return (MAP_FAILED);
	}
	return (va);
}

static int	nu_fd = FD_UNAVAIL;

void *
nu_map(Lm_list *lml, caddr_t addr, size_t len, int prot, int flags)
{
	caddr_t	va;
	int	err;

	if (nu_fd == FD_UNAVAIL) {
		if ((nu_fd = open(MSG_ORIG(MSG_PTH_DEVNULL),
		    O_RDONLY)) == FD_UNAVAIL) {
			err = errno;
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    MSG_ORIG(MSG_PTH_DEVNULL), strerror(err));
			return (MAP_FAILED);
		}
	}

	if ((va = (caddr_t)mmap(addr, len, prot, flags, nu_fd, 0)) ==
	    MAP_FAILED) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_MMAP),
		    MSG_ORIG(MSG_PTH_DEVNULL), strerror(err));
	}
	return (va);
}

/*
 * Generic entry point from user code - simply grabs a lock, and bumps the
 * entrance count.
 */
int
enter(int flags)
{
	if (rt_bind_guard(THR_FLG_RTLD | thr_flg_nolock | flags)) {
		if (!thr_flg_nolock)
			(void) rt_mutex_lock(&rtldlock);
		if (rtld_flags & RT_FL_OPERATION) {
			ld_entry_cnt++;

			/*
			 * Reset the diagnostic time information for each new
			 * "operation".  Thus timing diagnostics are relative
			 * to entering ld.so.1.
			 */
			if (DBG_ISTIME() &&
			    (gettimeofday(&DBG_TOTALTIME, NULL) == 0)) {
				DBG_DELTATIME = DBG_TOTALTIME;
				DBG_ONRESET();
			}
		}
		return (1);
	}
	return (0);
}

/*
 * Determine whether a search path has been used.
 */
static void
is_path_used(Lm_list *lml, Word unref, int *nl, Alist *alp, const char *obj)
{
	Pdesc	*pdp;
	Aliste	idx;

	for (ALIST_TRAVERSE(alp, idx, pdp)) {
		const char	*fmt, *name;

		if ((pdp->pd_plen == 0) || (pdp->pd_flags & PD_FLG_USED))
			continue;

		/*
		 * If this pathname originated from an expanded token, use the
		 * original for any diagnostic output.
		 */
		if ((name = pdp->pd_oname) == NULL)
			name = pdp->pd_pname;

		if (unref == 0) {
			if ((*nl)++ == 0)
				DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));
			DBG_CALL(Dbg_unused_path(lml, name, pdp->pd_flags,
			    (pdp->pd_flags & PD_FLG_DUPLICAT), obj));
			continue;
		}

		if (pdp->pd_flags & LA_SER_LIBPATH) {
			if (pdp->pd_flags & LA_SER_CONFIG) {
				if (pdp->pd_flags & PD_FLG_DUPLICAT)
					fmt = MSG_INTL(MSG_DUP_LDLIBPATHC);
				else
					fmt = MSG_INTL(MSG_USD_LDLIBPATHC);
			} else {
				if (pdp->pd_flags & PD_FLG_DUPLICAT)
					fmt = MSG_INTL(MSG_DUP_LDLIBPATH);
				else
					fmt = MSG_INTL(MSG_USD_LDLIBPATH);
			}
		} else if (pdp->pd_flags & LA_SER_RUNPATH) {
			fmt = MSG_INTL(MSG_USD_RUNPATH);
		} else
			continue;

		if ((*nl)++ == 0)
			(void) printf(MSG_ORIG(MSG_STR_NL));
		(void) printf(fmt, name, obj);
	}
}

/*
 * Generate diagnostics as to whether an object has been used.  A symbolic
 * reference that gets bound to an object marks it as used.  Dependencies that
 * are unused when RTLD_NOW is in effect should be removed from future builds
 * of an object.  Dependencies that are unused without RTLD_NOW in effect are
 * candidates for lazy-loading.
 *
 * Unreferenced objects identify objects that are defined as dependencies but
 * are unreferenced by the caller.  These unreferenced objects may however be
 * referenced by other objects within the process, and therefore don't qualify
 * as completely unused.  They are still an unnecessary overhead.
 *
 * Unreferenced runpaths are also captured under ldd -U, or "unused,detail"
 * debugging.
 */
void
unused(Lm_list *lml)
{
	Rt_map		*lmp;
	int		nl = 0;
	Word		unref, unuse;

	/*
	 * If we're not tracing unused references or dependencies, or debugging
	 * there's nothing to do.
	 */
	unref = lml->lm_flags & LML_FLG_TRC_UNREF;
	unuse = lml->lm_flags & LML_FLG_TRC_UNUSED;

	if ((unref == 0) && (unuse == 0) && (DBG_ENABLED == 0))
		return;

	/*
	 * Detect unused global search paths.
	 */
	if (rpl_libdirs)
		is_path_used(lml, unref, &nl, rpl_libdirs, config->c_name);
	if (prm_libdirs)
		is_path_used(lml, unref, &nl, prm_libdirs, config->c_name);

	nl = 0;
	lmp = lml->lm_head;
	if (RLIST(lmp))
		is_path_used(lml, unref, &nl, RLIST(lmp), NAME(lmp));

	/*
	 * Traverse the link-maps looking for unreferenced or unused
	 * dependencies.  Ignore the first object on a link-map list, as this
	 * is always used.
	 */
	nl = 0;
	for (lmp = NEXT_RT_MAP(lmp); lmp; lmp = NEXT_RT_MAP(lmp)) {
		/*
		 * Determine if this object contains any runpaths that have
		 * not been used.
		 */
		if (RLIST(lmp))
			is_path_used(lml, unref, &nl, RLIST(lmp), NAME(lmp));

		/*
		 * If tracing unreferenced objects, or under debugging,
		 * determine whether any of this objects callers haven't
		 * referenced it.
		 */
		if (unref || DBG_ENABLED) {
			Bnd_desc	*bdp;
			Aliste		idx;

			for (APLIST_TRAVERSE(CALLERS(lmp), idx, bdp)) {
				Rt_map	*clmp;

				if (bdp->b_flags & BND_REFER)
					continue;

				clmp = bdp->b_caller;
				if (FLAGS1(clmp) & FL1_RT_LDDSTUB)
					continue;

				/* BEGIN CSTYLED */
				if (nl++ == 0) {
					if (unref)
					    (void) printf(MSG_ORIG(MSG_STR_NL));
					else
					    DBG_CALL(Dbg_util_nl(lml,
						DBG_NL_STD));
				}

				if (unref)
				    (void) printf(MSG_INTL(MSG_LDD_UNREF_FMT),
					NAME(lmp), NAME(clmp));
				else
				    DBG_CALL(Dbg_unused_unref(lmp, NAME(clmp)));
				/* END CSTYLED */
			}
		}

		/*
		 * If tracing unused objects simply display those objects that
		 * haven't been referenced by anyone.
		 */
		if (FLAGS1(lmp) & FL1_RT_USED)
			continue;

		if (nl++ == 0) {
			if (unref || unuse)
				(void) printf(MSG_ORIG(MSG_STR_NL));
			else
				DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));
		}
		if (CYCGROUP(lmp)) {
			if (unref || unuse)
				(void) printf(MSG_INTL(MSG_LDD_UNCYC_FMT),
				    NAME(lmp), CYCGROUP(lmp));
			else
				DBG_CALL(Dbg_unused_file(lml, NAME(lmp), 0,
				    CYCGROUP(lmp)));
		} else {
			if (unref || unuse)
				(void) printf(MSG_INTL(MSG_LDD_UNUSED_FMT),
				    NAME(lmp));
			else
				DBG_CALL(Dbg_unused_file(lml, NAME(lmp), 0, 0));
		}
	}

	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));
}

/*
 * Generic cleanup routine called prior to returning control to the user.
 * Ensures that any ld.so.1 specific file descriptors or temporary mapping are
 * released, and any locks dropped.
 */
void
leave(Lm_list *lml, int flags)
{
	/*
	 * Alert the debuggers that the link-maps are consistent.
	 */
	rd_event(lml, RD_DLACTIVITY, RT_CONSISTENT);

	/*
	 * Alert any auditors that the link-maps are consistent.
	 */
	if (lml->lm_flags & LML_FLG_ACTAUDIT) {
		audit_activity(lml->lm_head, LA_ACT_CONSISTENT);
		lml->lm_flags &= ~LML_FLG_ACTAUDIT;
	}

	if (nu_fd != FD_UNAVAIL) {
		(void) close(nu_fd);
		nu_fd = FD_UNAVAIL;
	}

	/*
	 * Reinitialize error message pointer, and any overflow indication.
	 */
	nextptr = errbuf;
	prevptr = NULL;

	/*
	 * Defragment any freed memory.
	 */
	if (aplist_nitems(free_alp))
		defrag();

	/*
	 * Don't drop our lock if we are running on our link-map list as
	 * there's little point in doing so since we are single-threaded.
	 *
	 * LML_FLG_HOLDLOCK is set for:
	 *  -	 The ld.so.1's link-map list.
	 *  -	 The auditor's link-map if the environment is pre-UPM.
	 */
	if (lml->lm_flags & LML_FLG_HOLDLOCK)
		return;

	if (rt_bind_clear(0) & THR_FLG_RTLD) {
		if (!thr_flg_nolock)
			(void) rt_mutex_unlock(&rtldlock);
		(void) rt_bind_clear(THR_FLG_RTLD | thr_flg_nolock | flags);
	}
}

int
callable(Rt_map *clmp, Rt_map *dlmp, Grp_hdl *ghp, uint_t slflags)
{
	APlist		*calp, *dalp;
	Aliste		idx1, idx2;
	Grp_hdl		*ghp1, *ghp2;

	/*
	 * An object can always find symbols within itself.
	 */
	if (clmp == dlmp)
		return (1);

	/*
	 * The search for a singleton must look in every loaded object.
	 */
	if (slflags & LKUP_SINGLETON)
		return (1);

	/*
	 * Don't allow an object to bind to an object that is being deleted
	 * unless the binder is also being deleted.
	 */
	if ((FLAGS(dlmp) & FLG_RT_DELETE) &&
	    ((FLAGS(clmp) & FLG_RT_DELETE) == 0))
		return (0);

	/*
	 * An object with world access can always bind to an object with global
	 * visibility.
	 */
	if (((MODE(clmp) & RTLD_WORLD) || (slflags & LKUP_WORLD)) &&
	    (MODE(dlmp) & RTLD_GLOBAL))
		return (1);

	/*
	 * An object with local access can only bind to an object that is a
	 * member of the same group.
	 */
	if (((MODE(clmp) & RTLD_GROUP) == 0) ||
	    ((calp = GROUPS(clmp)) == NULL) || ((dalp = GROUPS(dlmp)) == NULL))
		return (0);

	/*
	 * Traverse the list of groups the caller is a part of.
	 */
	for (APLIST_TRAVERSE(calp, idx1, ghp1)) {
		/*
		 * If we're testing for the ability of two objects to bind to
		 * each other regardless of a specific group, ignore that group.
		 */
		if (ghp && (ghp1 == ghp))
			continue;

		/*
		 * Traverse the list of groups the destination is a part of.
		 */
		for (APLIST_TRAVERSE(dalp, idx2, ghp2)) {
			Grp_desc	*gdp;
			Aliste		idx3;

			if (ghp1 != ghp2)
				continue;

			/*
			 * Make sure the relationship between the destination
			 * and the caller provide symbols for relocation.
			 * Parents are maintained as callers, but unless the
			 * destination object was opened with RTLD_PARENT, the
			 * parent doesn't provide symbols for the destination
			 * to relocate against.
			 */
			for (ALIST_TRAVERSE(ghp2->gh_depends, idx3, gdp)) {
				if (dlmp != gdp->gd_depend)
					continue;

				if (gdp->gd_flags & GPD_RELOC)
					return (1);
			}
		}
	}
	return (0);
}

/*
 * Initialize the environ symbol.  Traditionally this is carried out by the crt
 * code prior to jumping to main.  However, init sections get fired before this
 * variable is initialized, so ld.so.1 sets this directly from the AUX vector
 * information.  In addition, a process may have multiple link-maps (ld.so.1's
 * debugging and preloading objects), and link auditing, and each may need an
 * environ variable set.
 *
 * This routine is called after a relocation() pass, and thus provides for:
 *
 *  -	setting environ on the main link-map after the initial application and
 *	its dependencies have been established.  Typically environ lives in the
 *	application (provided by its crt), but in older applications it might
 *	be in libc.  Who knows what's expected of applications not built on
 *	Solaris.
 *
 *  -	after loading a new shared object.  We can add shared objects to various
 *	link-maps, and any link-map dependencies requiring getopt() require
 *	their own environ.  In addition, lazy loading might bring in the
 *	supplier of environ (libc used to be a lazy loading candidate) after
 *	the link-map has been established and other objects are present.
 *
 * This routine handles all these scenarios, without adding unnecessary overhead
 * to ld.so.1.
 */
void
set_environ(Lm_list *lml)
{
	Slookup		sl;
	Sresult		sr;
	uint_t		binfo;

	/*
	 * Initialize the symbol lookup, and symbol result, data structures.
	 */
	SLOOKUP_INIT(sl, MSG_ORIG(MSG_SYM_ENVIRON), lml->lm_head, lml->lm_head,
	    ld_entry_cnt, 0, 0, 0, 0, LKUP_WEAK);
	SRESULT_INIT(sr, MSG_ORIG(MSG_SYM_ENVIRON));

	if (LM_LOOKUP_SYM(lml->lm_head)(&sl, &sr, &binfo, 0)) {
		Rt_map	*dlmp = sr.sr_dmap;

		lml->lm_environ = (char ***)sr.sr_sym->st_value;

		if (!(FLAGS(dlmp) & FLG_RT_FIXED))
			lml->lm_environ =
			    (char ***)((uintptr_t)lml->lm_environ +
			    (uintptr_t)ADDR(dlmp));
		*(lml->lm_environ) = (char **)environ;
		lml->lm_flags |= LML_FLG_ENVIRON;
	}
}

/*
 * Determine whether we have a secure executable.  Uid and gid information
 * can be passed to us via the aux vector, however if these values are -1
 * then use the appropriate system call to obtain them.
 *
 *  -	If the user is the root they can do anything
 *
 *  -	If the real and effective uid's don't match, or the real and
 *	effective gid's don't match then this is determined to be a `secure'
 *	application.
 *
 * This function is called prior to any dependency processing (see _setup.c).
 * Any secure setting will remain in effect for the life of the process.
 */
void
security(uid_t uid, uid_t euid, gid_t gid, gid_t egid, int auxflags)
{
	if (auxflags != -1) {
		if ((auxflags & AF_SUN_SETUGID) != 0)
			rtld_flags |= RT_FL_SECURE;
		return;
	}

	if (uid == (uid_t)-1)
		uid = getuid();
	if (uid) {
		if (euid == (uid_t)-1)
			euid = geteuid();
		if (uid != euid)
			rtld_flags |= RT_FL_SECURE;
		else {
			if (gid == (gid_t)-1)
				gid = getgid();
			if (egid == (gid_t)-1)
				egid = getegid();
			if (gid != egid)
				rtld_flags |= RT_FL_SECURE;
		}
	}
}

/*
 * Determine whether ld.so.1 itself is owned by root and has its mode setuid.
 */
int
is_rtld_setuid()
{
	rtld_stat_t	status;
	const char	*name;

	if (rtld_flags2 & RT_FL2_SETUID)
		return (1);

	if (interp && interp->i_name)
		name = interp->i_name;
	else
		name = NAME(lml_rtld.lm_head);

	if (((rtld_stat(name, &status) == 0) &&
	    (status.st_uid == 0) && (status.st_mode & S_ISUID))) {
		rtld_flags2 |= RT_FL2_SETUID;
		return (1);
	}
	return (0);
}

/*
 * Determine that systems platform name.  Normally, this name is provided from
 * the AT_SUN_PLATFORM aux vector from the kernel.  This routine provides a
 * fall back.
 */
void
platform_name(Syscapset *scapset)
{
	char	info[SYS_NMLN];
	size_t	size;

	if ((scapset->sc_platsz = size =
	    sysinfo(SI_PLATFORM, info, SYS_NMLN)) == (size_t)-1)
		return;

	if ((scapset->sc_plat = malloc(size)) == NULL) {
		scapset->sc_platsz = (size_t)-1;
		return;
	}
	(void) strcpy(scapset->sc_plat, info);
}

/*
 * Determine that systems machine name.  Normally, this name is provided from
 * the AT_SUN_MACHINE aux vector from the kernel.  This routine provides a
 * fall back.
 */
void
machine_name(Syscapset *scapset)
{
	char	info[SYS_NMLN];
	size_t	size;

	if ((scapset->sc_machsz = size =
	    sysinfo(SI_MACHINE, info, SYS_NMLN)) == (size_t)-1)
		return;

	if ((scapset->sc_mach = malloc(size)) == NULL) {
		scapset->sc_machsz = (size_t)-1;
		return;
	}
	(void) strcpy(scapset->sc_mach, info);
}

/*
 * _REENTRANT code gets errno redefined to a function so provide for return
 * of the thread errno if applicable.  This has no meaning in ld.so.1 which
 * is basically singled threaded.  Provide the interface for our dependencies.
 */
#undef errno
int *
___errno()
{
	extern	int	errno;

	return (&errno);
}

/*
 * Determine whether a symbol name should be demangled.
 */
const char *
demangle(const char *name)
{
	if (rtld_flags & RT_FL_DEMANGLE)
		return (conv_demangle_name(name));
	else
		return (name);
}

#ifndef _LP64
/*
 * Wrappers on stat() and fstat() for 32-bit rtld that uses stat64()
 * underneath while preserving the object size limits of a non-largefile
 * enabled 32-bit process. The purpose of this is to prevent large inode
 * values from causing stat() to fail.
 */
inline static int
rtld_stat_process(int r, struct stat64 *lbuf, rtld_stat_t *restrict buf)
{
	extern int	errno;

	/*
	 * Although we used a 64-bit capable stat(), the 32-bit rtld
	 * can only handle objects < 2GB in size. If this object is
	 * too big, turn the success into an overflow error.
	 */
	if ((lbuf->st_size & 0xffffffff80000000) != 0) {
		errno = EOVERFLOW;
		return (-1);
	}

	/*
	 * Transfer the information needed by rtld into a rtld_stat_t
	 * structure that preserves the non-largile types for everything
	 * except inode.
	 */
	buf->st_dev = lbuf->st_dev;
	buf->st_ino = lbuf->st_ino;
	buf->st_mode = lbuf->st_mode;
	buf->st_uid = lbuf->st_uid;
	buf->st_size = (off_t)lbuf->st_size;
	buf->st_mtim = lbuf->st_mtim;
#ifdef sparc
	buf->st_blksize = lbuf->st_blksize;
#endif

	return (r);
}

int
rtld_stat(const char *restrict path, rtld_stat_t *restrict buf)
{
	struct stat64	lbuf;
	int		r;

	r = stat64(path, &lbuf);
	if (r != -1)
		r = rtld_stat_process(r, &lbuf, buf);
	return (r);
}

int
rtld_fstat(int fildes, rtld_stat_t *restrict buf)
{
	struct stat64	lbuf;
	int		r;

	r = fstat64(fildes, &lbuf);
	if (r != -1)
		r = rtld_stat_process(r, &lbuf, buf);
	return (r);
}
#endif
