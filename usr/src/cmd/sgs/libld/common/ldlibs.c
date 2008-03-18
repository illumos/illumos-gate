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
 * Library processing
 */
#include	<stdio.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<string.h>
#include	<limits.h>
#include	<errno.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * List of support libraries specified (-S option).
 */
static Listnode *	insert_lib;

/*
 * Function to handle -YL and -YU substitutions in LIBPATH.  It's probably
 * very unlikely that the link-editor will ever see this, as any use of these
 * options is normally processed by the compiler driver first and the finished
 * -YP string is sent to us.  The fact that these two options are not even
 * documented anymore makes it even more unlikely this processing will occur.
 */
static char *
compat_YL_YU(Ofl_desc *ofl, char *path, int index)
{
	if (index == YLDIR) {
		if (Llibdir) {
			/*
			 * User supplied "-YL,libdir", this is the pathname that
			 * corresponds for compatibility to -YL (as defined in
			 * sgs/include/paths.h)
			 */
			DBG_CALL(Dbg_libs_ylu(ofl->ofl_lml, Llibdir,
			    path, index));
			return (Llibdir);
		}
	} else if (index == YUDIR) {
		if (Ulibdir) {
			/*
			 * User supplied "-YU,libdir", this is the pathname that
			 * corresponds for compatibility to -YU (as defined in
			 * sgs/include/paths.h)
			 */
			DBG_CALL(Dbg_libs_ylu(ofl->ofl_lml, Ulibdir,
			    path, index));
			return (Ulibdir);
		}
	}
	return (path);
}

static char *
process_lib_path(Ofl_desc *ofl, List *list, char *path, Boolean subsflag)
{
	int	i;
	char	*cp;
	Boolean	seenflg = FALSE;
	char	*dot = (char *)MSG_ORIG(MSG_STR_DOT);

	for (i = YLDIR; i; i++) {
		cp = strpbrk(path, MSG_ORIG(MSG_STR_PATHTOK));
		if (cp == NULL) {
			if (*path == '\0') {
				if (seenflg)
					if (list_appendc(list, subsflag ?
					    compat_YL_YU(ofl, dot, i) : dot) ==
					    0)
						return ((char *)S_ERROR);
			} else
				if (list_appendc(list, subsflag ?
				    compat_YL_YU(ofl, path, i) : path) == 0)
					return ((char *)S_ERROR);
			return (cp);
		}

		if (*cp == ':') {
			*cp = '\0';
			if (cp == path) {
				if (list_appendc(list, subsflag ?
				    compat_YL_YU(ofl, dot, i) : dot) == 0)
					return ((char *)S_ERROR);
			} else {
				if (list_appendc(list, subsflag ?
				    compat_YL_YU(ofl, path, i) : path) == 0)
					return ((char *)S_ERROR);
			}
			path = cp + 1;
			seenflg = TRUE;
			continue;
		}

		/* case ";" */

		if (cp != path) {
			if (list_appendc(list, subsflag ?
			    compat_YL_YU(ofl, path, i) : path) == 0)
				return ((char *)S_ERROR);
		} else {
			if (seenflg)
				if (list_appendc(list, subsflag ?
				    compat_YL_YU(ofl, dot, i) : dot) == 0)
					return ((char *)S_ERROR);
		}
		return (cp);
	}
	/* NOTREACHED */
	return (NULL);	/* keep gcc happy */
}

/*
 * adds the indicated path to those to be searched for libraries.
 */
uintptr_t
ld_add_libdir(Ofl_desc *ofl, const char *path)
{
	if (insert_lib == NULL) {
		if (list_prependc(&ofl->ofl_ulibdirs, path) == 0)
			return (S_ERROR);
		insert_lib = ofl->ofl_ulibdirs.head;
	} else
		if ((insert_lib = list_insertc(&ofl->ofl_ulibdirs, path,
		    insert_lib)) == 0)
			return (S_ERROR);

	/*
	 * As -l and -L options can be interspersed, print the library
	 * search paths each time a new path is added.
	 */
	DBG_CALL(Dbg_libs_update(ofl->ofl_lml, &ofl->ofl_ulibdirs,
	    &ofl->ofl_dlibdirs));
	return (1);
}

/*
 * Process a required library.  Combine the directory and filename, and then
 * append either a `.so' or `.a' suffix and try opening the associated pathname.
 */
static Ifl_desc *
find_lib_name(const char *dir, const char *file, Ofl_desc *ofl, Rej_desc *rej)
{
	int		fd;
	size_t		dlen;
	char		*_path, path[PATH_MAX + 2];
	const char	*_dir = dir;
	Ifl_desc	*ifl;

	/*
	 * Determine the size of the directory.  The directory and filename are
	 * concatenated into the local buffer which is purposely larger than
	 * PATH_MAX.  Should a pathname be created that exceeds the system
	 * limit, the open() will catch it, and a suitable rejection message is
	 * saved.
	 */
	if ((dlen = strlen(dir)) == 0) {
		_dir = (char *)MSG_ORIG(MSG_STR_DOT);
		dlen = 1;
	}
	dlen++;

	/*
	 * If we are in dynamic mode try and open the associated shared object.
	 */
	if (ofl->ofl_flags & FLG_OF_DYNLIBS) {
		(void) snprintf(path, (PATH_MAX + 2), MSG_ORIG(MSG_STR_LIB_SO),
		    _dir, file);
		DBG_CALL(Dbg_libs_l(ofl->ofl_lml, file, path));
		if ((fd = open(path, O_RDONLY)) != -1) {

			if ((_path = libld_malloc(strlen(path) + 1)) == 0)
				return ((Ifl_desc *)S_ERROR);
			(void) strcpy(_path, path);

			ifl = ld_process_open(_path, &_path[dlen], &fd, ofl,
			    FLG_IF_NEEDED, rej);
			if (fd != -1)
				(void) close(fd);
			return (ifl);

		} else if (errno != ENOENT) {
			/*
			 * If the open() failed for anything other than the
			 * file not existing, record the error condition.
			 */
			rej->rej_type = SGS_REJ_STR;
			rej->rej_str = strerror(errno);
			rej->rej_name = strdup(path);
		}
	}

	/*
	 * If we are not in dynamic mode, or a shared object could not be
	 * located, try and open the associated archive.
	 */
	(void) snprintf(path, (PATH_MAX + 2), MSG_ORIG(MSG_STR_LIB_A),
	    _dir, file);
	DBG_CALL(Dbg_libs_l(ofl->ofl_lml, file, path));
	if ((fd = open(path, O_RDONLY)) != -1) {

		if ((_path = libld_malloc(strlen(path) + 1)) == 0)
			return ((Ifl_desc *)S_ERROR);
		(void) strcpy(_path, path);

		ifl = ld_process_open(_path, &_path[dlen], &fd, ofl,
		    FLG_IF_NEEDED, rej);
		if (fd != -1)
			(void) close(fd);
		return (ifl);

	} else if (errno != ENOENT) {
		/*
		 * If the open() failed for anything other than the
		 * file not existing, record the error condition.
		 */
		rej->rej_type = SGS_REJ_STR;
		rej->rej_str = strerror(errno);
		rej->rej_name = strdup(path);
	}

	return (0);
}

/*
 * Take the abbreviated name of a library file (from -lfoo) and searches for the
 * library.  The search path rules are:
 *
 *	o	use any user supplied paths, i.e. LD_LIBRARY_PATH and -L, then
 *
 *	o	use the default directories, i.e. LIBPATH or -YP.
 *
 * If we are in dynamic mode and -Bstatic is not in effect, first look for a
 * shared object with full name: path/libfoo.so; then [or else] look for an
 * archive with name: path/libfoo.a.  If no file is found, it's a fatal error,
 * otherwise process the file appropriately depending on its type.
 */
uintptr_t
ld_find_library(const char *name, Ofl_desc *ofl)
{
	Listnode	*lnp;
	char		*path;
	Ifl_desc	*ifl = 0;
	Rej_desc	rej = { 0 };

	/*
	 * Search for this file in any user defined directories.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_ulibdirs, lnp, path)) {
		Rej_desc	_rej = { 0 };

		if ((ifl = find_lib_name(path, name, ofl, &_rej)) == 0) {
			if (_rej.rej_type && (rej.rej_type == 0))
				rej = _rej;
			continue;
		}
		return ((uintptr_t)ifl);
	}

	/*
	 * Finally try the default library search directories.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_dlibdirs, lnp, path)) {
		Rej_desc	_rej = { 0 };

		if ((ifl = find_lib_name(path, name, ofl, &_rej)) == 0) {
			if (_rej.rej_type && (rej.rej_type == 0))
				rej = _rej;
			continue;
		}
		return ((uintptr_t)ifl);
	}

	/*
	 * If we've got this far we haven't found a shared object or archive.
	 * If an object was found, but was rejected for some reason, print a
	 * diagnostic to that effect, otherwise generate a generic "not found"
	 * diagnostic.
	 */
	if (rej.rej_type) {
		Conv_reject_desc_buf_t rej_buf;

		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(reject[rej.rej_type]),
		    rej.rej_name ? rej.rej_name : MSG_INTL(MSG_STR_UNKNOWN),
		    conv_reject_desc(&rej, &rej_buf, ld_targ.t_m.m_mach));
	} else {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_LIB_NOTFOUND),
		    name);
	}

	ofl->ofl_flags |= FLG_OF_FATAL;
	return (0);
}

/*
 * Inspect the LD_LIBRARY_PATH variable (if the -i options has not been
 * specified), and set up the directory list from which to search for
 * libraries.  From the man page:
 *
 *	LD_LIBRARY_PATH=dirlist1;dirlist2
 * and
 *	ld ... -Lpath1 ... -Lpathn ...
 *
 * results in a search order of:
 *
 *	dirlist1 path1 ... pathn dirlist2 LIBPATH
 *
 * If LD_LIBRARY_PATH has no `;' specified, the pathname(s) supplied are
 * all taken as dirlist2.
 */
uintptr_t
ld_lib_setup(Ofl_desc * ofl)
{
	char	*path, *cp = NULL;

	/*
	 * Determine whether an LD_LIBRARY_PATH setting is in effect.
	 */
	if (!(ofl->ofl_flags & FLG_OF_IGNENV)) {
#if	defined(_ELF64)
		if ((cp = getenv(MSG_ORIG(MSG_LD_LIBPATH_64))) == NULL)
#else
		if ((cp = getenv(MSG_ORIG(MSG_LD_LIBPATH_32))) == NULL)
#endif
			cp  = getenv(MSG_ORIG(MSG_LD_LIBPATH));
	}

	if ((cp != NULL) && (*cp != '\0')) {
		if ((path = libld_malloc(strlen(cp) + 1)) == 0)
			return (S_ERROR);
		(void) strcpy(path, cp);
		DBG_CALL(Dbg_libs_path(ofl->ofl_lml, path, LA_SER_DEFAULT, 0));

		/*
		 * Process the first path string (anything up to a null or
		 * a `;');
		 */
		path = process_lib_path(ofl, &ofl->ofl_ulibdirs, path, FALSE);


		/*
		 * If a `;' was seen then initialize the insert flag to the
		 * tail of this list.  This is where any -L paths will be
		 * added (otherwise -L paths are prepended to this list).
		 * Continue to process the remaining path string.
		 */
		if (path) {
			insert_lib = ofl->ofl_ulibdirs.tail;
			*path = '\0';
			++path;
			cp = process_lib_path(ofl, &ofl->ofl_ulibdirs, path,
			    FALSE);
			if (cp == (char *)S_ERROR)
				return (S_ERROR);
			else if (cp)
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_LIB_MALFORM));
		}
	}

	/*
	 * Add the default LIBPATH or any -YP supplied path.
	 */
	DBG_CALL(Dbg_libs_yp(ofl->ofl_lml, Plibpath));
	cp = process_lib_path(ofl, &ofl->ofl_dlibdirs, Plibpath, TRUE);
	if (cp == (char *)S_ERROR)
		return (S_ERROR);
	else if (cp) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_LIB_BADYP));
		return (S_ERROR);
	}
	DBG_CALL(Dbg_libs_init(ofl->ofl_lml, &ofl->ofl_ulibdirs,
	    &ofl->ofl_dlibdirs));
	return (1);
}
